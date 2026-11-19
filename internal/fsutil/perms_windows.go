// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build windows

package fsutil

import "os"

// FileOwnership reports no unix ownership on Windows, which has no unix
// uids/gids; the storeperm ownership checks that use it are unix-only. File
// protection comes from NTFS ACLs on the user profile rather than unix
// permission bits.
func FileOwnership(_ os.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}
