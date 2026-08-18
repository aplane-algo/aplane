// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"errors"

	"golang.org/x/sys/unix"
)

func renameBackupExportNoReplace(tmpPath, destination string) error {
	return unix.RenamexNp(tmpPath, destination, unix.RENAME_EXCL)
}

func backupExportNoReplaceUnsupported(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP)
}
