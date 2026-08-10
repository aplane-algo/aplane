// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "golang.org/x/sys/unix"

func renameBackupExportNoReplace(tmpPath, destination string) error {
	return unix.RenamexNp(tmpPath, destination, unix.RENAME_EXCL)
}
