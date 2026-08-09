// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package fsutil provides filesystem helpers for the aplane store.
package fsutil

import (
	"os"
)

// StoreDirPerm is the permission mode for store directories.
const StoreDirPerm = os.ModeSetgid | 0770

// StoreFilePerm is the permission mode for store files.
const StoreFilePerm os.FileMode = 0660

// MkdirAll creates a directory and all parents with store permissions (g+rwx, setgid).
// Unlike os.MkdirAll, this explicitly sets permissions after creation to
// bypass umask restrictions. If the directory already exists, permissions
// are left unchanged (the caller may not own it).
func MkdirAll(path string) error {
	// Check if directory already exists — skip chmod if so, since we may
	// not own it (e.g., apstore restore run by a group member).
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil
	}

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

// WriteFile writes data using the explicitly legacy shared-store profile.
// New signer-private code should use WriteFileDurableWithProfile with
// PrivateStoreFileProfile instead. This compatibility entry point remains
// while legacy stores are migrated to service-user-only ownership.
func WriteFile(path string, data []byte) error {
	return WriteFileDurableWithProfile(path, data, LegacyStoreFileProfile)
}
