// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package fsutil provides filesystem helpers for the aplane store.
// Store files use group-accessible permissions (0660 files, 0770 dirs)
// so that any member of the aplane group can manage the store while
// apsigner can read/write through group ownership.
package fsutil

import (
	"os"
	"path/filepath"
	"syscall"
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

// WriteFile writes data to a file with store permissions (g+rw).
// It replaces the target atomically so crashes leave either the old file or
// the new file, never a truncated partially-written target.
func WriteFile(path string, data []byte) error {
	info, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
			// Shared-group update of someone else's file: preserve ownership by
			// writing in place, matching the pre-atomic behavior.
			return writeFileInPlace(path, data)
		}
	case os.IsNotExist(statErr):
		// New file: use atomic replace path below.
	default:
		return statErr
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}

	targetMode := StoreFilePerm
	var targetGID int
	hasOwnership := false

	switch {
	case statErr == nil:
		targetMode = info.Mode().Perm()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			targetGID = int(stat.Gid)
			hasOwnership = targetGID != os.Getgid()
		}
	case os.IsNotExist(statErr):
		// New file: keep default mode and current ownership.
	default:
		return statErr
	}

	if err := tmp.Chmod(targetMode); err != nil {
		return err
	}
	if hasOwnership {
		if err := tmp.Chown(-1, targetGID); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func writeFileInPlace(path string, data []byte) error {
	if err := os.WriteFile(path, data, StoreFilePerm); err != nil {
		return err
	}
	return os.Chmod(path, StoreFilePerm)
}
