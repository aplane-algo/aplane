// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !windows

package clientdata

import (
	"os"
	"syscall"
)

// lockFileExclusive takes an exclusive advisory flock on the open lock file,
// blocking until it is available. The returned func releases the lock.
func lockFileExclusive(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}, nil
}
