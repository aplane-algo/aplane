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
	return rejectIfInsecureDirectory(socketPath, false)
}

// ValidatePrivateRuntimeBindPath applies the target multi-UID production
// contract: the socket parent is a real directory owned by the daemon user and
// is not writable by group or other users.
func ValidatePrivateRuntimeBindPath(socketPath string) error {
	if err := validateSocketPath(socketPath); err != nil {
		return err
	}
	return rejectIfInsecureDirectory(socketPath, true)
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
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("SECURITY: existing socket path is not a socket: %s", socketPath)
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

// rejectIfInsecureDirectory rejects unsafe socket parents. strict additionally
// requires daemon ownership and rejects group write access.
func rejectIfInsecureDirectory(socketPath string, strict bool) error {
	dir := filepath.Dir(socketPath)

	// Check for common world-writable directories
	if strings.HasPrefix(dir, "/tmp") || strings.HasPrefix(dir, "/var/tmp") {
		return fmt.Errorf("refusing IPC socket in world-writable directory: %s (use $XDG_RUNTIME_DIR or a private runtime directory)", socketPath)
	}

	// Check actual directory permissions
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("failed to inspect IPC socket directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing IPC socket parent that is not a real directory: %s", dir)
	}

	// Check if directory is world-writable (others have write permission)
	if info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("refusing IPC socket in world-writable directory: %s", dir)
	}
	if strict {
		if info.Mode().Perm()&0o020 != 0 {
			return fmt.Errorf("refusing IPC socket in group-writable directory: %s", dir)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot determine IPC socket directory owner: %s", dir)
		}
		if stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("refusing IPC socket directory owned by uid %d, expected %d: %s", stat.Uid, os.Getuid(), dir)
		}
	}
	return nil
}
