// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package fsutil provides filesystem helpers for the aplane store.
// Store files use group-accessible permissions (0660 files, 0770 dirs)
// so that any member of the aplane group can manage the store while
// apsignerd can read/write through group ownership.
package fsutil

import (
	"fmt"
	"os"
)

// StoreDirPerm is the permission mode for store directories.
const StoreDirPerm = os.ModeSetgid | 0770

// StoreFilePerm is the permission mode for store files.
const StoreFilePerm os.FileMode = 0660

// MkdirAll creates a directory and all parents with store permissions (g+rwx, setgid).
// Unlike os.MkdirAll, this explicitly sets permissions after creation to
// bypass umask restrictions.
func MkdirAll(path string) error {
	if err := os.MkdirAll(path, 0770); err != nil {
		return err
	}
	// Set setgid + 0770. Setgid requires ownership or root; if we lack
	// permission, fall back to 0770 without setgid.
	if err := os.Chmod(path, StoreDirPerm); err != nil {
		if os.IsPermission(err) {
			return os.Chmod(path, 0770)
		}
		return err
	}
	return nil
}

// WriteFile writes data to a file with store permissions (g+rw).
// Unlike os.WriteFile, this explicitly sets permissions after creation to
// bypass umask restrictions.
func WriteFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, StoreFilePerm); err != nil {
		return err
	}
	return os.Chmod(path, StoreFilePerm)
}

// CreateFile opens a file for writing with store permissions (g+rw).
// Returns the opened file. Caller is responsible for closing it.
func CreateFile(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag, StoreFilePerm)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(StoreFilePerm); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}
	return f, nil
}
