// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package fsutil

import (
	"os"
	"path/filepath"
)

// HookOp identifies a durability-relevant operation intercepted by TestHook.
type HookOp string

const (
	// OpFileSync precedes fsync of a written temp file.
	OpFileSync HookOp = "file-sync"
	// OpDirSync precedes fsync of a directory.
	OpDirSync HookOp = "dir-sync"
	// OpRename precedes the rename that publishes a durable write.
	OpRename HookOp = "rename"
)

// TestHook, when non-nil, runs before each durability-relevant operation in
// this package's durable helpers; returning an error aborts that operation
// with the error. Tests use it to assert operation ordering and to inject
// failures at exact crash points. It must be nil in production and is not
// synchronized: set it before concurrent use and clear it after.
var TestHook func(op HookOp, path string) error

func runHook(op HookOp, path string) error {
	if TestHook != nil {
		return TestHook(op, path)
	}
	return nil
}

// WriteFileDurable writes data to path atomically and durably: temp file in
// the destination directory, fsync of the file, rename over the destination,
// fsync of the parent directory. On return the new content survives a crash
// or power loss.
//
// Unlike WriteFile it never falls back to an unsynced in-place write. When
// the destination exists, its mode and group ownership are preserved through
// the replacement; a destination owned by another uid becomes owned by the
// writing process (group access is what the store's permission model
// guarantees, and a silent unsynced fallback is not acceptable on paths that
// require durability).
func WriteFileDurable(path string, data []byte) error {
	info, statErr := os.Stat(path)
	if statErr != nil && !os.IsNotExist(statErr) {
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
	targetGID := 0
	hasOwnership := false
	if statErr == nil {
		targetMode = info.Mode().Perm()
		if _, gid, ok := FileOwnership(info); ok {
			targetGID = gid
			hasOwnership = targetGID != os.Getgid()
		}
	}

	if err := tmp.Chmod(targetMode); err != nil {
		return err
	}
	if hasOwnership {
		if err := tmp.Chown(-1, targetGID); err != nil {
			return err
		}
	}

	if err := runHook(OpFileSync, path); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := runHook(OpRename, path); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return SyncDir(dir)
}

// SyncFile fsyncs an existing file's data and metadata. Use it when a file
// was written or modified through a path that does not sync (plain writes,
// chmod/chown fix-ups) and its content must survive a power loss before a
// subsequent rename publishes it.
func SyncFile(path string) error {
	if err := runHook(OpFileSync, path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// SyncDir fsyncs the directory at path, making previously renamed, created,
// or removed entries durable. Platforms without directory fsync (Windows)
// treat it as a no-op.
func SyncDir(path string) error {
	if err := runHook(OpDirSync, path); err != nil {
		return err
	}
	return syncDir(path)
}

// RemoveDurable removes path and fsyncs its parent directory so the removal
// survives a crash. A path that does not exist is not an error: the removal
// it records is already the state on disk.
func RemoveDurable(path string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return SyncDir(filepath.Dir(path))
}
