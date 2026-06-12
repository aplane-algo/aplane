// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build windows

package fsutil

import "os"

// FileOwnership reports no unix ownership on Windows: there are no unix
// uids/gids, so the shared-group preservation logic is skipped and writes
// always take the atomic-replace path. File protection comes from NTFS ACLs
// on the user profile rather than unix permission bits.
func FileOwnership(_ os.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}
