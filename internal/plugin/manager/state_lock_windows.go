// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build windows

package manager

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func tryLockPluginStateFile(file *os.File) (func(), error) {
	handle := windows.Handle(file.Fd())
	overlapped := new(windows.Overlapped)
	err := windows.LockFileEx(
		handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errPluginStateLockHeld
		}
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, new(windows.Overlapped))
	}, nil
}
