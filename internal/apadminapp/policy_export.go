// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// ExportedPolicyDocument is one active policy document as the daemon returned
// it, with the digest its policy summary listed for it.
type ExportedPolicyDocument struct {
	Key      string
	Document string
	SHA256   string
}

// ErrPolicyChangedDuringExport reports that the documents fetched for an
// export are not the policy set the summary described: an apply landed while
// they were being read.
var ErrPolicyChangedDuringExport = errors.New("the policy changed while it was being exported; refresh and export again")

// ExportPolicyFileName is the file a document is exported as: default.json
// for the node default, <key>.json for a key's own document.
func ExportPolicyFileName(key string) (string, error) {
	if key != policy.DefaultKey {
		if err := storepaths.ValidatePolicySelector(key); err != nil {
			return "", fmt.Errorf("policy document key %q cannot be a file name: %w", key, err)
		}
	}
	return key + ".json", nil
}

// ExportPolicyDocuments writes a node's active policy documents into dir, one
// file per document, exactly as stored, with mode 0600. dir must not exist
// (its parent must) or must be an empty directory; it is never merged into,
// so an export never mixes with older files. Before anything is written,
// every document must match the digest its summary listed and together they
// must be the summary's policy set (setSHA256), so a policy that changed
// during the export is refused rather than written as a mix. It returns the
// paths written, in document order.
func ExportPolicyDocuments(dir string, docs []ExportedPolicyDocument, setSHA256 string) ([]string, error) {
	if dir == "" {
		return nil, fmt.Errorf("an export directory is required")
	}
	stored := make([]policy.StoredDocument, 0, len(docs))
	names := make([]string, 0, len(docs))
	seen := make(map[string]bool, len(docs))
	for _, doc := range docs {
		name, err := ExportPolicyFileName(doc.Key)
		if err != nil {
			return nil, err
		}
		if seen[doc.Key] {
			return nil, fmt.Errorf("policy document %q is listed twice", doc.Key)
		}
		seen[doc.Key] = true
		sum := sha256.Sum256([]byte(doc.Document))
		if hex.EncodeToString(sum[:]) != doc.SHA256 {
			return nil, ErrPolicyChangedDuringExport
		}
		stored = append(stored, policy.StoredDocument{Key: doc.Key, Bytes: []byte(doc.Document)})
		names = append(names, name)
	}
	if policy.PolicySetSHA256(stored) != setSHA256 {
		return nil, ErrPolicyChangedDuringExport
	}
	if err := prepareExportDir(dir); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(docs))
	for i, doc := range stored {
		path := filepath.Join(dir, names[i])
		if err := fsutil.WriteFileDurableWithProfile(path, doc.Bytes, fsutil.PrivateStoreFileProfile); err != nil {
			return paths, fmt.Errorf("write %s: %w", path, err)
		}
		paths = append(paths, path)
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
