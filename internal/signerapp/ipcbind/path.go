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
	_, err := ResolveBindPath(socketPath)
	return err
}

// ResolveBindPath resolves trusted directory aliases and returns the canonical
// socket path after validating both the alias chain and its target. Callers
// must bind the returned path rather than traversing the original aliases
// again after validation.
func ResolveBindPath(socketPath string) (string, error) {
	absSocket, err := filepath.Abs(filepath.Clean(socketPath))
	if err != nil {
		return "", fmt.Errorf("resolve IPC socket path: %w", err)
	}
	originalParent := filepath.Dir(absSocket)
	resolvedParent, err := filepath.EvalSymlinks(originalParent)
	if err != nil {
		return "", fmt.Errorf("resolve IPC socket directory %s: %w", originalParent, err)
	}
	resolvedParent, err = filepath.Abs(filepath.Clean(resolvedParent))
	if err != nil {
		return "", fmt.Errorf("resolve canonical IPC socket directory: %w", err)
	}
	resolvedSocket := filepath.Join(resolvedParent, filepath.Base(absSocket))

	if err := validateSocketPath(resolvedSocket); err != nil {
		return "", err
	}
	tempRoots := trustedStickyTempRoots()
	if err := validateRealSocketDirectoryChain(resolvedSocket, tempRoots); err != nil {
		return "", err
	}
	if originalParent != resolvedParent {
		if err := validateSocketAliasChain(absSocket, tempRoots); err != nil {
			return "", err
		}
	}
	return resolvedSocket, nil
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

// validateRealSocketDirectoryChain ensures an untrusted local user cannot replace
// the socket after its leaf has been inspected. The immediate parent must be
// daemon-owned. Every ancestor must be owned by either the daemon or the owner
// of the filesystem root and must not be group/other writable. The canonical
// shared temporary roots are the sole exception when they are owned by the
// filesystem-root owner and carry the sticky bit.
func validateRealSocketDirectoryChain(socketPath string, tempRoots map[string]struct{}) error {
	absSocket, err := filepath.Abs(filepath.Clean(socketPath))
	if err != nil {
		return fmt.Errorf("resolve IPC socket path: %w", err)
	}
	parent := filepath.Dir(absSocket)
	if isSharedTempRoot(parent, tempRoots) {
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
		} else if isTrustedStickyTempRoot(path, info, owner, rootUID, tempRoots) {
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

// validateSocketAliasChain permits a platform or administrator supplied
// directory symlink only when the link itself has a trusted owner, every real
// lexical component has the normal directory protections, and the resolved
// target chain has already passed validateRealSocketDirectoryChain.
func validateSocketAliasChain(socketPath string, tempRoots map[string]struct{}) error {
	parent := filepath.Dir(socketPath)
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
			return fmt.Errorf("failed to inspect IPC socket alias component %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			owner, err := filesystemObjectOwner(path, info)
			if err != nil {
				return err
			}
			if owner != currentUID && owner != rootUID {
				return fmt.Errorf("refusing IPC socket symlink owned by unrelated uid %d: %s", owner, path)
			}
		} else {
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
			} else if isTrustedStickyTempRoot(path, info, owner, rootUID, tempRoots) {
				// The sticky directory protects its current/root-owned alias.
			} else {
				if owner != currentUID && owner != rootUID {
					return fmt.Errorf("refusing IPC socket beneath directory owned by unrelated uid %d: %s", owner, path)
				}
				if info.Mode().Perm()&0o022 != 0 {
					return fmt.Errorf("refusing IPC socket beneath group/other-writable directory: %s", path)
				}
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
	return filesystemObjectOwner(path, info)
}

func filesystemObjectOwner(path string, info os.FileInfo) (int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot determine IPC socket path owner: %s", path)
	}
	return int(stat.Uid), nil
}

func trustedStickyTempRoots() map[string]struct{} {
	roots := make(map[string]struct{}, 2)
	for _, path := range []string{"/tmp", "/var/tmp"} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		resolved, err = filepath.Abs(filepath.Clean(resolved))
		if err == nil {
			roots[resolved] = struct{}{}
		}
	}
	return roots
}

func isSharedTempRoot(path string, tempRoots map[string]struct{}) bool {
	_, ok := tempRoots[path]
	return ok
}

func isTrustedStickyTempRoot(path string, info os.FileInfo, owner, rootUID int, tempRoots map[string]struct{}) bool {
	return isSharedTempRoot(path, tempRoots) && owner == rootUID && info.Mode()&os.ModeSticky != 0
}
