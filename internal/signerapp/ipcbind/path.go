// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ipcbind

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ValidateBindPath checks whether socketPath is safe to remove and bind.
func ValidateBindPath(socketPath string) error {
	if err := validateSocketPath(socketPath); err != nil {
		return err
	}
	return validateSocketDirectoryChain(socketPath)
}

// ValidatePrivateRuntimeBindPath applies the target multi-UID production
// contract: the socket parent is a real directory owned by the daemon user and
// is not writable by group or other users.
func ValidatePrivateRuntimeBindPath(socketPath string) error {
	if err := validateSocketPath(socketPath); err != nil {
		return err
	}
	return validateSocketDirectoryChain(socketPath)
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

// validateSocketDirectoryChain ensures an untrusted local user cannot replace
// the socket after its leaf has been inspected. The immediate parent must be
// daemon-owned. Every ancestor must be owned by either the daemon or the owner
// of the filesystem root and must not be group/other writable. The canonical
// shared temporary roots are the sole exception when they are owned by the
// filesystem-root owner and carry the sticky bit.
func validateSocketDirectoryChain(socketPath string) error {
	absSocket, err := filepath.Abs(filepath.Clean(socketPath))
	if err != nil {
		return fmt.Errorf("resolve IPC socket path: %w", err)
	}
	parent := filepath.Dir(absSocket)
	if parent == "/tmp" || parent == "/var/tmp" {
		return fmt.Errorf("refusing IPC socket directly in shared temporary directory: %s (use $XDG_RUNTIME_DIR or a private runtime directory)", socketPath)
	}

	currentUID := os.Getuid()
	if currentUID < 0 {
		return fmt.Errorf("invalid UID: %d", currentUID)
	}
	rootInfo, err := os.Lstat(string(filepath.Separator))
	if err != nil {
		return fmt.Errorf("inspect filesystem root for IPC socket: %w", err)
	}
	rootUID, err := realDirectoryOwner(string(filepath.Separator), rootInfo)
	if err != nil {
		return err
	}

	for path := parent; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to inspect IPC socket directory %s: %w", path, err)
		}
		owner, err := realDirectoryOwner(path, info)
		if err != nil {
			return err
		}

		if path == parent {
			if owner != currentUID {
				return fmt.Errorf("refusing IPC socket directory owned by uid %d, expected %d: %s", owner, currentUID, path)
			}
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("refusing IPC socket in group/other-writable directory: %s", path)
			}
		} else if isTrustedStickyTempRoot(path, info, owner, rootUID) {
			// Root-owned sticky temporary directories protect entries owned by
			// other users from rename/unlink by unrelated users.
		} else {
			if owner != currentUID && owner != rootUID {
				return fmt.Errorf("refusing IPC socket beneath directory owned by unrelated uid %d: %s", owner, path)
			}
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("refusing IPC socket beneath group/other-writable directory: %s", path)
			}
		}

		if path == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func realDirectoryOwner(path string, info os.FileInfo) (int, error) {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, fmt.Errorf("refusing IPC socket path component that is not a real directory: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot determine IPC socket directory owner: %s", path)
	}
	return int(stat.Uid), nil
}

func isTrustedStickyTempRoot(path string, info os.FileInfo, owner, rootUID int) bool {
	return (path == "/tmp" || path == "/var/tmp") &&
		owner == rootUID && info.Mode()&os.ModeSticky != 0
}
