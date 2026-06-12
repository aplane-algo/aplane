// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"os"
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

// WriteConfigAtomic writes a config file via a temp file and rename so
// readers never observe a partial write.
func WriteConfigAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "config.yaml.tmp-*")
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

	targetMode := mode
	var targetUID, targetGID int
	hasOwnership := false

	info, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		targetMode = info.Mode().Perm()
		if uid, gid, ok := fsutil.FileOwnership(info); ok {
			targetUID = uid
			targetGID = gid
			hasOwnership = true
		}
	case os.IsNotExist(statErr):
		// New file: keep default mode and current ownership.
	default:
		return statErr
	}

	if err := tmp.Chmod(targetMode); err != nil {
		return err
	}
	if hasOwnership && (os.Getuid() != targetUID || os.Getgid() != targetGID) {
		if err := tmp.Chown(targetUID, targetGID); err != nil {
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
