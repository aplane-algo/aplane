//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"golang.org/x/sys/unix"
)

func openManagedServicePrincipal(root string) (*os.File, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open signer store root: %w", err)
	}
	rootFile := os.NewFile(uintptr(rootFD), root)
	if rootFile == nil {
		_ = unix.Close(rootFD)
		return nil, fmt.Errorf("wrap signer store root descriptor")
	}
	defer func() { _ = rootFile.Close() }()

	installFD, err := unix.Openat(rootFD, "install", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open root-controlled install metadata directory: %w", err)
	}
	installFile := os.NewFile(uintptr(installFD), "install")
	if installFile == nil {
		_ = unix.Close(installFD)
		return nil, fmt.Errorf("wrap install metadata directory descriptor")
	}
	defer func() { _ = installFile.Close() }()
	if err := requireOpenedRootControlledPath(installFile, true); err != nil {
		return nil, fmt.Errorf("validate install metadata directory: %w", err)
	}

	principalFD, err := unix.Openat(installFD, "service-principal.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open root-controlled service principal file: %w", err)
	}
	principalFile := os.NewFile(uintptr(principalFD), ServicePrincipalRelativePath)
	if principalFile == nil {
		_ = unix.Close(principalFD)
		return nil, fmt.Errorf("wrap service principal descriptor")
	}
	if err := requireOpenedRootControlledPath(principalFile, false); err != nil {
		_ = principalFile.Close()
		return nil, fmt.Errorf("validate service principal file: %w", err)
	}
	return principalFile, nil
}

func requireOpenedRootControlledPath(file *os.File, directory bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("unexpected filesystem object type")
	}
	uid, _, ok := fsutil.FileOwnership(info)
	if !ok {
		return fmt.Errorf("ownership metadata unavailable")
	}
	if uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("path is not root-controlled")
	}
	return nil
}
