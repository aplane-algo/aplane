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

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
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
// the policy set the summary described, or with the context do not make the
// snapshot the node reported: something changed while they were being read.
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

// Write exports a node's active policy documents into dir: one file per
// document, exactly as stored, and the node's context ctx in
// .appolicy/node.json. dir must not exist (its parent must) or must be an
// empty directory; it is never merged into, so an export never mixes with
// older files. Files are mode 0600 and directories 0700.
//
// setSHA256 and snapshotSHA256 are the policy set and composite snapshot
// digests the node reported with its summary and context. Before anything
// is written, every document must match the digest the summary listed,
// together they must be that policy set, and with ctx they must make that
// snapshot, so a policy or context that changed during the export is
// refused rather than written as a mix. The context
// file is written last, after an in-progress marker and every document are
// durable, and the marker is then removed: a failed export leaves the marker,
// and is never mistaken for a complete one. It returns the paths of the
// documents written, in document order.
func Write(dir string, docs []Document, ctx *policycontext.Context, setSHA256, snapshotSHA256 string, at time.Time) ([]string, error) {
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
	if policy.PolicySetSHA256(stored) != setSHA256 {
		return nil, ErrPolicyChanged
	}
	export, err := policycontext.NewExport(ctx, digests, at)
	if err != nil {
		return nil, err
	}
	if export.Baseline.SnapshotSHA256 != snapshotSHA256 {
		return nil, ErrPolicyChanged
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
