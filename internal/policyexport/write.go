// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyexport writes a node's policy export and finds the context
// an export left for the files in it. An export is a directory of the node's
// policy documents, exactly as stored, with the node's policy context in
// .appolicy/node.json; apadmin writes it, and appolicy and apadmin read the
// context back when they check or apply files from it.
package policyexport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// An export's context lives in ContextDir: ContextFile once the export is
// complete, and InProgressFile while it is being written.
const (
	ContextDir     = ".appolicy"
	ContextFile    = "node.json"
	InProgressFile = "export-in-progress"
)

// Document is one active policy document as the node returned it, with the
// digest its policy summary listed for it.
type Document struct {
	Key      string
	Document string
	SHA256   string
}

// ErrPolicyChanged reports that the documents fetched for an export are not
// the policy set the summary described: an apply landed while they were
// being read.
var ErrPolicyChanged = errors.New("the policy changed while it was being exported; refresh and export again")

// FileName is the file a document is exported as: default.json for the node
// default, <key>.json for a key's own document.
func FileName(key string) (string, error) {
	if key != policy.DefaultKey {
		if err := storepaths.ValidatePolicySelector(key); err != nil {
			return "", fmt.Errorf("policy document key %q cannot be a file name: %w", key, err)
		}
	}
	return key + ".json", nil
}

// ContextFromView is the context a node described, checked against the
// digests it sent with it: a context whose contents do not produce its own
// digest, or a snapshot that is not the context's with its policy set, is
// refused rather than exported.
func ContextFromView(view adminproto.PolicyContextView) (*policycontext.Context, error) {
	if !view.Success {
		return nil, fmt.Errorf("the node's policy context is unavailable: %s", view.Error)
	}
	networks := make(map[string]asaset.GenesisHash, len(view.Networks))
	for _, n := range view.Networks {
		genesis, err := asaset.ParseGenesisHash(n.GenesisHash)
		if err != nil {
			return nil, fmt.Errorf("network %q: %w", n.Network, err)
		}
		if _, dup := networks[n.Network]; dup {
			return nil, fmt.Errorf("network %q is listed twice", n.Network)
		}
		networks[n.Network] = genesis
	}
	assets := make([]asaset.Asset, 0, len(view.Assets))
	for _, a := range view.Assets {
		genesis, err := asaset.ParseGenesisHash(a.GenesisHash)
		if err != nil {
			return nil, fmt.Errorf("asset %d: %w", a.AssetID, err)
		}
		assets = append(assets, asaset.Asset{
			Identity: asaset.Identity{Genesis: genesis, AssetID: a.AssetID},
			Name:     a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Origin: asaset.Origin(a.Origin),
		})
	}
	table, err := asaset.NewTable(assets)
	if err != nil {
		return nil, err
	}
	ctx, err := policycontext.FromParts(noderole.Role(view.NodeRole), networks, table, view.RulesVersion)
	if err != nil {
		return nil, err
	}
	if ctx.SHA256() != view.ContextSHA256 {
		return nil, errors.New("the node's policy context does not match its context_sha256")
	}
	if policycontext.SnapshotSHA256(view.ContextSHA256, view.PolicySetSHA256) != view.SnapshotSHA256 {
		return nil, errors.New("the node's snapshot_sha256 is not its context's with its policy set")
	}
	return ctx, nil
}

// ViewFromMessage is the policy context a get_policy_context reply carries,
// the inverse of the server's projection onto the wire.
func ViewFromMessage(msg protocol.PolicyContextMessage) adminproto.PolicyContextView {
	view := adminproto.PolicyContextView{
		Success: msg.Success, NodeRole: msg.NodeRole, RulesVersion: msg.RulesVersion,
		ContextSHA256: msg.ContextSHA256, PolicySetSHA256: msg.PolicySetSHA256, SnapshotSHA256: msg.SnapshotSHA256,
		Code: msg.Code, Error: msg.Error,
	}
	for _, n := range msg.Networks {
		view.Networks = append(view.Networks, adminproto.PolicyNetwork{Network: n.Network, GenesisHash: n.GenesisHash})
	}
	for _, a := range msg.Assets {
		view.Assets = append(view.Assets, adminproto.ASAInfo{
			Network: a.Network, GenesisHash: a.GenesisHash, AssetID: a.AssetID, Name: a.Name,
			UnitName: a.UnitName, Decimals: a.Decimals, Origin: a.Origin,
		})
	}
	return view
}

// Write exports a node's active policy documents into dir: one file per
// document, exactly as stored, and the node's context in
// .appolicy/node.json. dir must not exist (its parent must) or must be an
// empty directory; it is never merged into, so an export never mixes with
// older files. Files are mode 0600 and directories 0700.
//
// Before anything is written, every document must match the digest the
// summary listed, together they must be the policy set the context names,
// and the context must match its own digests, so a policy that changed
// during the export is refused rather than written as a mix. The context
// file is written last, after an in-progress marker and every document are
// durable, and the marker is then removed: a failed export leaves the marker,
// and is never mistaken for a complete one. It returns the paths of the
// documents written, in document order.
func Write(dir string, docs []Document, view adminproto.PolicyContextView, at time.Time) ([]string, error) {
	if dir == "" {
		return nil, fmt.Errorf("an export directory is required")
	}
	stored := make([]policy.StoredDocument, 0, len(docs))
	digests := make([]policy.DocumentDigest, 0, len(docs))
	names := make([]string, 0, len(docs))
	seen := make(map[string]bool, len(docs))
	for _, doc := range docs {
		name, err := FileName(doc.Key)
		if err != nil {
			return nil, err
		}
		if seen[doc.Key] {
			return nil, fmt.Errorf("policy document %q is listed twice", doc.Key)
		}
		seen[doc.Key] = true
		sum := sha256.Sum256([]byte(doc.Document))
		if hex.EncodeToString(sum[:]) != doc.SHA256 {
			return nil, ErrPolicyChanged
		}
		stored = append(stored, policy.StoredDocument{Key: doc.Key, Bytes: []byte(doc.Document)})
		digests = append(digests, policy.DocumentDigest{Key: doc.Key, SHA256: doc.SHA256})
		names = append(names, name)
	}
	if policy.PolicySetSHA256(stored) != view.PolicySetSHA256 {
		return nil, ErrPolicyChanged
	}
	ctx, err := ContextFromView(view)
	if err != nil {
		return nil, err
	}
	export, err := policycontext.NewExport(ctx, digests, at)
	if err != nil {
		return nil, err
	}
	contextBytes, err := export.Marshal()
	if err != nil {
		return nil, err
	}

	if err := prepareExportDir(dir); err != nil {
		return nil, err
	}
	contextDir := filepath.Join(dir, ContextDir)
	if err := os.Mkdir(contextDir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", contextDir, err)
	}
	marker := filepath.Join(contextDir, InProgressFile)
	started := []byte("export started " + export.ExportedAt.Format(time.RFC3339) + "\n")
	if err := fsutil.WriteFileDurableWithProfile(marker, started, fsutil.PrivateStoreFileProfile); err != nil {
		return nil, fmt.Errorf("write %s: %w", marker, err)
	}
	paths := make([]string, 0, len(docs))
	for i, doc := range stored {
		path := filepath.Join(dir, names[i])
		if err := fsutil.WriteFileDurableWithProfile(path, doc.Bytes, fsutil.PrivateStoreFileProfile); err != nil {
			return paths, fmt.Errorf("write %s: %w", path, err)
		}
		paths = append(paths, path)
	}
	contextPath := filepath.Join(contextDir, ContextFile)
	if err := fsutil.WriteFileDurableWithProfile(contextPath, contextBytes, fsutil.PrivateStoreFileProfile); err != nil {
		return paths, fmt.Errorf("write %s: %w", contextPath, err)
	}
	if err := fsutil.RemoveDurable(marker); err != nil {
		return paths, fmt.Errorf("finish the export: %w", err)
	}
	return paths, nil
}

// prepareExportDir creates dir with mode 0700, or accepts it when it is an
// existing empty directory (not a symlink to one).
func prepareExportDir(dir string) error {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("create export directory: %w", err)
		}
		return nil
	case err != nil:
		return err
	case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
		return fmt.Errorf("%s exists and is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty; export into a new or empty directory", dir)
	}
	return nil
}
