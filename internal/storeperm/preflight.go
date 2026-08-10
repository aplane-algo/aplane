// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"fmt"
	"os"
	"path/filepath"
)

// PreflightResult summarizes a read-only legacy-store structural inspection.
type PreflightResult struct {
	Inspected int
}

// PreflightLegacy validates the filesystem shape of a stopped legacy signer
// store before a privileged installer writes any store-relative path. The
// caller must first close group/other access at the store root so the
// inventory cannot be raced by a former group member.
//
// Unix sockets are inert during this inspection and are left for the later
// configured-socket migration policy to classify. No file is opened for
// content and this function never mutates the store.
func PreflightLegacy(rootPath string) (PreflightResult, error) {
	if rootPath == "" {
		return PreflightResult{}, fmt.Errorf("store root is required")
	}
	root, err := filepath.Abs(filepath.Clean(rootPath))
	if err != nil {
		return PreflightResult{}, fmt.Errorf("resolve store root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("inspect store root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return PreflightResult{}, fmt.Errorf("signer data directory is not a real directory: %s", root)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return PreflightResult{}, fmt.Errorf(
			"signer data directory must be closed to group and other before structural preflight: %s has mode %04o",
			root,
			info.Mode().Perm(),
		)
	}

	entries, err := structuralInventory(root, "preflight", func(_ string, candidate os.FileInfo) bool {
		return candidate.Mode()&os.ModeSocket != 0
	})
	if err != nil {
		return PreflightResult{}, err
	}
	return PreflightResult{Inspected: len(entries)}, nil
}
