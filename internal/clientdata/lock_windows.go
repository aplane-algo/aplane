// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build windows

package clientdata

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFileExclusive takes an exclusive lock on the first byte of the open
// lock file via LockFileEx, blocking until it is available. The returned
// func releases the lock. This mirrors the advisory flock semantics used on
// unix: only writers that participate are serialized.
func lockFileExclusive(f *os.File) (func(), error) {
	handle := windows.Handle(f.Fd())
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, new(windows.Overlapped))
	}, nil
}
