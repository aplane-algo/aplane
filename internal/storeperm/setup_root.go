// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"golang.org/x/sys/unix"
)

// PrepareManagedRootResult summarizes safe creation and closure of a managed
// signer-store root before legacy-tree preflight.
type PrepareManagedRootResult struct {
	Path    string
	Created bool
}

// PrepareManagedRoot creates any missing path components beneath trusted
// ancestors, then changes ownership and mode through an opened descriptor for
// the final directory. It rejects symlinked, unrelated-owner, and writable
// ancestors before performing a privileged pathname mutation beneath them.
func PrepareManagedRoot(rootPath string, uid, gid int) (PrepareManagedRootResult, error) {
	return prepareManagedRoot(rootPath, uid, gid, nil)
}

func prepareManagedRoot(rootPath string, uid, gid int, beforeOwnership func()) (PrepareManagedRootResult, error) {
	if rootPath == "" {
		return PrepareManagedRootResult{}, fmt.Errorf("store root is required")
	}
	root, err := filepath.Abs(filepath.Clean(rootPath))
	if err != nil {
		return PrepareManagedRootResult{}, fmt.Errorf("resolve store root: %w", err)
	}
	if root == string(filepath.Separator) {
		return PrepareManagedRootResult{}, fmt.Errorf("filesystem root cannot be used as the signer data directory")
	}

	current, err := os.Open(string(filepath.Separator))
	if err != nil {
		return PrepareManagedRootResult{}, fmt.Errorf("open filesystem root: %w", err)
	}
	defer func() { _ = current.Close() }()
	var finalParent *os.File
	defer func() {
		if finalParent != nil {
			_ = finalParent.Close()
		}
	}()
	rootInfo, err := current.Stat()
	if err != nil {
		return PrepareManagedRootResult{}, fmt.Errorf("inspect filesystem root: %w", err)
	}
	rootUID, _, ok := fsutil.FileOwnership(rootInfo)
	if !ok {
		return PrepareManagedRootResult{}, fmt.Errorf("cannot determine filesystem root ownership")
	}

	components := strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator))
	currentPath := string(filepath.Separator)
	createdRoot := false
	for index, component := range components {
		final := index == len(components)-1
		if err := validateManagedSetupAncestor(currentPath, current, uid, rootUID); err != nil {
			return PrepareManagedRootResult{}, err
		}

		nextFD, openErr := unix.Openat(
			int(current.Fd()),
			component,
			unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
			0,
		)
		if errors.Is(openErr, syscall.ENOENT) {
			mode := uint32(0o755)
			if final {
				mode = 0o700
			}
			if err := unix.Mkdirat(int(current.Fd()), component, mode); err != nil {
				return PrepareManagedRootResult{}, fmt.Errorf("create signer data path component %s: %w", filepath.Join(currentPath, component), err)
			}
			if err := current.Sync(); err != nil {
				return PrepareManagedRootResult{}, fmt.Errorf("sync signer data parent %s: %w", currentPath, err)
			}
			if final {
				createdRoot = true
			}
			nextFD, openErr = unix.Openat(
				int(current.Fd()),
				component,
				unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
				0,
			)
		}
		if openErr != nil {
			return PrepareManagedRootResult{}, fmt.Errorf("open real signer data path component %s: %w", filepath.Join(currentPath, component), openErr)
		}
		next := os.NewFile(uintptr(nextFD), filepath.Join(currentPath, component))
		if next == nil {
			_ = unix.Close(nextFD)
			return PrepareManagedRootResult{}, fmt.Errorf("open signer data path component %s", filepath.Join(currentPath, component))
		}
		if final {
			// Retain the final parent so the leaf can be reopened relative to the
			// same trusted directory after ownership changes. This is necessary
			// for a root directly beneath an allowed sticky temporary directory.
			finalParent = current
		} else if err := current.Close(); err != nil {
			_ = next.Close()
			return PrepareManagedRootResult{}, fmt.Errorf("close signer data ancestor %s: %w", currentPath, err)
		}
		current = next
		currentPath = filepath.Join(currentPath, component)
	}

	if beforeOwnership != nil {
		beforeOwnership()
	}
	// Chown can clear mode bits, so ownership is applied first. Both operations
	// target the opened directory rather than resolving rootPath again.
	if err := current.Chown(uid, gid); err != nil {
		return PrepareManagedRootResult{}, fmt.Errorf("set signer data root ownership: %w", err)
	}
	openedInfo, err := current.Stat()
	if err != nil {
		return PrepareManagedRootResult{}, fmt.Errorf("inspect opened signer data root: %w", err)
	}
	if err := verifyManagedRootBinding(finalParent, filepath.Base(root), openedInfo, root); err != nil {
		return PrepareManagedRootResult{}, err
	}
	if err := current.Chmod(0o700); err != nil {
		return PrepareManagedRootResult{}, fmt.Errorf("close signer data root permissions: %w", err)
	}
	if err := current.Sync(); err != nil {
		return PrepareManagedRootResult{}, fmt.Errorf("sync signer data root: %w", err)
	}
	return PrepareManagedRootResult{Path: root, Created: createdRoot}, nil
}

func verifyManagedRootBinding(parent *os.File, leaf string, openedInfo os.FileInfo, root string) error {
	if parent == nil {
		return fmt.Errorf("signer data root parent is unavailable: %s", root)
	}
	pathFD, err := unix.Openat(
		int(parent.Fd()),
		leaf,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("reopen prepared signer data root %s: %w", root, err)
	}
	pathFile := os.NewFile(uintptr(pathFD), root)
	if pathFile == nil {
		_ = unix.Close(pathFD)
		return fmt.Errorf("reopen prepared signer data root %s", root)
	}
	defer func() { _ = pathFile.Close() }()
	pathInfo, err := pathFile.Stat()
	if err != nil {
		return fmt.Errorf("inspect rebound signer data root %s: %w", root, err)
	}
	if !os.SameFile(openedInfo, pathInfo) {
		return fmt.Errorf("signer data root changed during managed setup: %s", root)
	}
	return nil
}

func validateManagedSetupAncestor(path string, dir *os.File, serviceUID, rootUID int) error {
	if path == string(filepath.Separator) {
		return nil
	}
	info, err := dir.Stat()
	if err != nil {
		return fmt.Errorf("inspect signer-store ancestor %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("signer-store ancestor is not a directory: %s", path)
	}
	ownerUID, _, ok := fsutil.FileOwnership(info)
	if !ok {
		return fmt.Errorf("cannot determine signer-store ancestor ownership: %s", path)
	}
	if isTrustedStickyTempRoot(path, info, ownerUID, rootUID, trustedStickyTempRoots()) {
		return nil
	}
	if ownerUID != serviceUID && ownerUID != rootUID {
		return fmt.Errorf("signer-store ancestor %s is owned by unrelated uid %d", path, ownerUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("signer-store ancestor is group/other writable: %s", path)
	}
	return nil
}
