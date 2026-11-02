// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestBackupCreatedTimePrefersNameOverFileTime(t *testing.T) {
	file := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	named := protocol.BackupInfo{FileName: "aplane-backup-20261102-065558.428714630.tar.gz", CreatedAt: file.Unix()}
	if got, source := BackupCreatedTime(named); source != BackupTimeName ||
		!got.Equal(time.Date(2026, 11, 2, 6, 55, 58, 428714630, time.UTC)) {
		t.Fatalf("BackupCreatedTime(managed name) = %v, %s", got, source.Label())
	}
	renamed := protocol.BackupInfo{FileName: "lab.tar.gz", CreatedAt: file.Unix()}
	if got, source := BackupCreatedTime(renamed); source != BackupTimeFile || !got.Equal(file) {
		t.Fatalf("BackupCreatedTime(renamed) = %v, %s", got, source.Label())
	}
}

func TestStoreBackupListShowsCreatedTimeAndSource(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		if _, ok := message.(protocol.ListBackupsMessage); !ok {
			return errors.New("unexpected request")
		}
		*result.(*protocol.BackupsListMessage) = protocol.BackupsListMessage{Backups: []protocol.BackupInfo{
			{FileName: "aplane-backup-20261102-070725.tar.gz", Size: 10, Checksum: "aa"},
			{FileName: "lab.tar.gz", Size: 10, Checksum: "bb", CreatedAt: time.Date(2026, 10, 30, 18, 2, 11, 0, time.UTC).Unix()},
		}}
		return nil
	}}
	var stdout bytes.Buffer
	store := Store{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &bytes.Buffer{}}}
	if err := store.RunBackup([]string{"list"}); err != nil {
		t.Fatal(err)
	}
	want := "aplane-backup-20261102-070725.tar.gz  10 B  aa  2026-11-02T07:07:25Z  from name\n" +
		"lab.tar.gz  10 B  bb  2026-10-30T18:02:11Z  file time\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}
