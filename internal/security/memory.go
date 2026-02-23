// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package security

import (
	"fmt"
	"os"
	"syscall"
)

// LockMemory attempts to lock all memory pages to prevent swapping to disk
// This is critical for preventing private keys from being written to swap
func LockMemory() error {
	// Try to lock all current and future memory pages
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		return fmt.Errorf("mlockall failed: %w\n\nTo fix this, run:\n  sudo setcap cap_ipc_lock+ep %s", err, os.Args[0])
	}
	return nil
}

// DisableCoreDumps prevents core dumps which could leak private keys
func DisableCoreDumps() error {
	var rlimit syscall.Rlimit
	rlimit.Max = 0
	rlimit.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rlimit); err != nil {
		return fmt.Errorf("failed to disable core dumps: %w", err)
	}
	return nil
}
