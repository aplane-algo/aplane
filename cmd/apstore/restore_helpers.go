// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "github.com/aplane-algo/aplane/internal/backup"

func resolveBackupKeysDir(source string) string {
	return backup.ResolveBackupKeysDir(source)
}

func prepareBackupSource(source string) (string, func(), error) {
	return backup.PrepareRestoreSource(source)
}
