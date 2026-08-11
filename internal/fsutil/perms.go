// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package fsutil provides filesystem helpers for the aplane store.
package fsutil

import (
	"os"
)

// StoreDirPerm is the service-user-only permission mode for signer-store
// directories.
const StoreDirPerm os.FileMode = 0o700

// StoreFilePerm is the service-user-only permission mode for signer-store files.
const StoreFilePerm os.FileMode = 0o600

// MkdirAll creates an owner-private directory tree without changing an
// existing directory's permissions. It is suitable for caller-owned client
// state where the process may not own a pre-existing shared root.
func MkdirAll(path string) error {
	if err := os.MkdirAll(path, StoreDirPerm); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return &os.PathError{Op: "mkdir", Path: path, Err: os.ErrInvalid}
	}
	return nil
}

// MkdirAllPrivate creates a signer-store directory tree and clamps the final
// directory to the StoreDirPerm ceiling. Existing owner permissions are never
// added; newly created final directories receive StoreDirPerm. The caller must
// own the store directory.
func MkdirAllPrivate(path string) error {
	info, err := os.Lstat(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := MkdirAll(path); err != nil {
		return err
	}
	if !existed {
		return os.Chmod(path, StoreDirPerm)
	}
	return os.Chmod(path, info.Mode().Perm()&StoreDirPerm)
}

// WriteFile atomically and durably publishes a private signer-store file.
func WriteFile(path string, data []byte) error {
	return WriteFileDurableWithProfile(path, data, PrivateStoreFileProfile)
}
