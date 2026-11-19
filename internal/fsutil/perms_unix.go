// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !windows

package fsutil

import (
	"os"
	"syscall"
)

// FileOwnership reports the unix uid/gid of a stat result, for storeperm's
// ownership checks and repairs. ok is false when the platform stat carries no
// unix ownership.
func FileOwnership(info os.FileInfo) (uid, gid int, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
