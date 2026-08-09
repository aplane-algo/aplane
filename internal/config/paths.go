// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// ResolvePath resolves a path relative to baseDir if not absolute.
// Returns path unchanged if empty or already absolute.
func ResolvePath(path, baseDir string) string {
	if path == "" || baseDir == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// WriteConfigAtomic durably replaces a private same-UID config file. It uses
// the shared private-store publication primitive so symlinks, permissive modes,
// and unsynced rename paths cannot become config-specific exceptions.
func WriteConfigAtomic(path string, data []byte) error {
	return fsutil.WriteFileDurableWithProfile(path, data, fsutil.PrivateStoreFileProfile)
}
