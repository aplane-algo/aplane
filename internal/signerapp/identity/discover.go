// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"fmt"
	"os"
	"path/filepath"
)

// ValidateProductIdentityLayout verifies the single-product identities root
// without following direct-entry symlinks. A missing identities directory or
// default directory is the supported blank-store state.
func ValidateProductIdentityLayout(dataRoot string, productID string) error {
	identitiesDir := filepath.Join(dataRoot, "identities")
	entries, err := os.ReadDir(identitiesDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read identities directory: %w", err)
	}

	for _, entry := range entries {
		path := filepath.Join(identitiesDir, entry.Name())
		if entry.Name() != productID {
			return fmt.Errorf("unsupported entry %q under identities: APlane supports only the %q product identity", entry.Name(), productID)
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return fmt.Errorf("inspect product identity entry %q: %w", entry.Name(), statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("product identity %q must be a real directory, not a symlink or other file type", productID)
		}
	}
	return nil
}
