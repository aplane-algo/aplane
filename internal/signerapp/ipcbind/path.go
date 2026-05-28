// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ipcbind

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ValidateBindPath checks whether socketPath is safe to remove and bind.
func ValidateBindPath(socketPath string) error {
	if err := validateSocketPath(socketPath); err != nil {
		return err
	}
	return rejectIfInsecureDirectory(socketPath)
}

// validateSocketPath checks for symlink attacks and ownership issues.
// This prevents an attacker from:
// 1. Creating a symlink at the socket path pointing to a sensitive file
// 2. Replacing a socket with one they control
func validateSocketPath(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if os.IsNotExist(err) {
		// Socket doesn't exist yet - safe to create
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to stat socket path: %w", err)
	}

	// Check for symlink attack
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SECURITY: socket path is a symlink (possible attack): %s", socketPath)
	}

	// Verify ownership - socket must be owned by current user
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		uid := os.Getuid()
		if uid < 0 {
			return fmt.Errorf("invalid UID: %d", uid)
		}
		currentUID := uint32(uid) // #nosec G115 - UIDs on Linux are 32-bit, safe conversion
		if stat.Uid != currentUID {
			return fmt.Errorf("SECURITY: socket owned by different user (uid %d, expected %d): %s",
				stat.Uid, currentUID, socketPath)
		}
	}

	return nil
}

// rejectIfInsecureDirectory rejects socket paths in world-writable directories.
func rejectIfInsecureDirectory(socketPath string) error {
	dir := filepath.Dir(socketPath)

	// Check for common world-writable directories
	if strings.HasPrefix(dir, "/tmp") || strings.HasPrefix(dir, "/var/tmp") {
		return fmt.Errorf("refusing IPC socket in world-writable directory: %s (use $XDG_RUNTIME_DIR or a private runtime directory)", socketPath)
	}

	// Check actual directory permissions
	info, err := os.Stat(dir)
	if err != nil {
		return nil // Can't check, skip hard failure
	}

	// Check if directory is world-writable (others have write permission)
	if info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("refusing IPC socket in world-writable directory: %s", dir)
	}
	return nil
}
