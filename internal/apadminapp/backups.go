// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// BackupTimeSource says where a listed backup's creation time came from.
type BackupTimeSource int

const (
	// BackupTimeName is the time in a managed archive's name, written when
	// the node created it.
	BackupTimeName BackupTimeSource = iota
	// BackupTimeFile is the archive file's modification time, for an archive
	// whose name carries no time. Copying the file changes it.
	BackupTimeFile
)

// Label is a short description of the source for listings.
func (s BackupTimeSource) Label() string {
	if s == BackupTimeName {
		return "from name"
	}
	return "file time"
}

// BackupCreatedTime is the creation time a listing knows for a backup without
// its export passphrase, and where it came from. The time sealed inside the
// backup needs the passphrase; a restore preview reports it.
func BackupCreatedTime(info protocol.BackupInfo) (time.Time, BackupTimeSource) {
	if t, ok := backup.ManagedArchiveNameTime(info.FileName); ok {
		return t, BackupTimeName
	}
	return time.Unix(info.CreatedAt, 0).UTC(), BackupTimeFile
}
