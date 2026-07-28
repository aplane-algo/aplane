// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !linux && !darwin

package backup

import (
	"fmt"
	"os"
)

// Server binaries are supported on Linux and Darwin, where
// openManagedBackupArchive rejects final-component symlinks atomically. Keep
// other targets buildable for shared-package tooling.
func openManagedBackupArchive(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("backup archive must be a regular file: %s", path)
	}
	return os.Open(path)
}
