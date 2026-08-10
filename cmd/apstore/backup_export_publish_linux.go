// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "golang.org/x/sys/unix"

func renameBackupExportNoReplace(tmpPath, destination string) error {
	return unix.Renameat2(
		unix.AT_FDCWD,
		tmpPath,
		unix.AT_FDCWD,
		destination,
		unix.RENAME_NOREPLACE,
	)
}
