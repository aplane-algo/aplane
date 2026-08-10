// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestCmdBackupCreateAllAllowsEmptyBackupResult(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		backupResult: protocol.BackupResultMessage{
			Success:     true,
			ArchivePath: "aplane-backup-empty.tar.gz",
			Verified:    true,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("export-passphrase\nexport-passphrase\n", func() error {
		return cmdBackupCreate([]string{"all"})
	}); err != nil {
		t.Fatalf("cmdBackupCreate(all) error = %v", err)
	}
	if strings.Join(fake.requests, ",") != protocol.MsgTypeBackup {
		t.Fatalf("requests = %v, want backup", fake.requests)
	}
	if len(fake.backupRequest.Addresses) != 0 {
		t.Fatalf("backup addresses = %v, want all/empty selection", fake.backupRequest.Addresses)
	}
}

func TestCmdBackupCreateAddressReportsMissingKey(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		backupResult: protocol.BackupResultMessage{
			Success: false,
			Code:    protocol.ResultCodeBackupFailed,
			Error:   "failed to export ADDR: key file not found",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("export-passphrase\nexport-passphrase\n", func() error {
		return cmdBackupCreate([]string{"address", "ADDR"})
	})
	if err == nil {
		t.Fatal("cmdBackupCreate(address) error = nil, want missing key failure")
	}
	if !strings.Contains(err.Error(), "key file not found") {
		t.Fatalf("cmdBackupCreate(address) error = %v, want missing key context", err)
	}
	if len(fake.backupRequest.Addresses) != 1 || fake.backupRequest.Addresses[0] != "ADDR" {
		t.Fatalf("backup addresses = %v, want [ADDR]", fake.backupRequest.Addresses)
	}
}

func TestCmdBackupListHandlesNoBackups(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		listBackupsResult: protocol.BackupsListMessage{},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := cmdBackupList(); err != nil {
		t.Fatalf("cmdBackupList() error = %v", err)
	}
	if strings.Join(fake.requests, ",") != protocol.MsgTypeListBackups {
		t.Fatalf("requests = %v, want list_backups", fake.requests)
	}
}

func TestCmdBackupExportRejectsBadDestinationBeforeIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{}
	withFakeApstoreAdminClient(t, fake)

	err := cmdBackupExport("backup.tar.gz", filepath.Join(t.TempDir(), "backup.tar.gz"))
	if err == nil {
		t.Fatal("cmdBackupExport() error = nil, want archive-path rejection")
	}
	if !strings.Contains(err.Error(), "destination must be a directory") {
		t.Fatalf("cmdBackupExport() error = %v, want directory context", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("requests = %v, want no IPC request before local validation failure", fake.requests)
	}
}

func TestCmdBackupExportCopiesChecksumMatchIntoDestinationDirectory(t *testing.T) {
	managedDir := t.TempDir()
	managedPath := filepath.Join(managedDir, "aplane-backup-20260423-010203.tar.gz")
	if err := os.WriteFile(managedPath, []byte("archive"), 0o600); err != nil {
		t.Fatalf("WriteFile(managed archive) error = %v", err)
	}
	checksum, size, err := backup.FileSHA256(managedPath)
	if err != nil {
		t.Fatalf("FileSHA256() error = %v", err)
	}
	fake := &fakeApstoreAdminRequester{
		backupExportData: []byte("archive"),
		listBackupsResult: protocol.BackupsListMessage{
			Backups: []protocol.BackupInfo{{
				FileName: "aplane-backup-20260423-010203.tar.gz",
				Path:     managedPath,
				Size:     size,
				Checksum: checksum,
			}},
		},
	}
	withFakeApstoreAdminClient(t, fake)

	destinationDir := filepath.Join(t.TempDir(), "exports")
	if err := cmdBackupExport(checksum, destinationDir); err != nil {
		t.Fatalf("cmdBackupExport(checksum) error = %v", err)
	}
	if strings.Join(fake.requests, ",") != protocol.MsgTypeListBackups+","+protocol.MsgTypeReadBackupChunk {
		t.Fatalf("requests = %v, want list_backups then read_backup_chunk", fake.requests)
	}
	exportedPath := filepath.Join(destinationDir, "aplane-backup-20260423-010203.tar.gz")
	exported, err := os.ReadFile(exportedPath)
	if err != nil {
		t.Fatalf("ReadFile(exported archive) error = %v", err)
	}
	if string(exported) != "archive" {
		t.Fatalf("exported archive = %q, want archive", string(exported))
	}
}

func TestCmdBackupExportDoesNotReplaceDestinationCreatedDuringTransfer(t *testing.T) {
	archive := []byte("archive")
	managedPath := filepath.Join(t.TempDir(), "aplane-backup-20260423-010203.tar.gz")
	if err := os.WriteFile(managedPath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	checksum, size, err := backup.FileSHA256(managedPath)
	if err != nil {
		t.Fatal(err)
	}
	destinationDir := t.TempDir()
	destination := filepath.Join(destinationDir, filepath.Base(managedPath))
	fake := &fakeApstoreAdminRequester{}
	fake.requestFunc = func(msg any, out any) error {
		switch typed := msg.(type) {
		case protocol.ListBackupsMessage:
			fake.requests = append(fake.requests, typed.Type)
			*out.(*protocol.BackupsListMessage) = protocol.BackupsListMessage{Backups: []protocol.BackupInfo{{
				FileName: filepath.Base(managedPath), Path: managedPath, Size: size, Checksum: checksum,
			}}}
			return nil
		case protocol.ReadBackupChunkMessage:
			fake.requests = append(fake.requests, typed.Type)
			if err := os.WriteFile(destination, []byte("concurrent output"), 0o600); err != nil {
				return err
			}
			*out.(*protocol.BackupChunkMessage) = protocol.BackupChunkMessage{
				Success: true, FileName: typed.FileName, Offset: typed.Offset, Data: archive, EOF: true,
			}
			return nil
		default:
			return errors.New("unexpected request")
		}
	}
	withFakeApstoreAdminClient(t, fake)

	err = cmdBackupExport(checksum, destinationDir)
	if err == nil || !strings.Contains(err.Error(), "destination already exists") {
		t.Fatalf("cmdBackupExport() error = %v, want no-replace failure", err)
	}
	got, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "concurrent output" {
		t.Fatalf("destination = %q, want concurrent output preserved", got)
	}
}

func TestCmdBackupDeleteCancellationSkipsIPCDelete(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		listBackupsResult: protocol.BackupsListMessage{
			Backups: []protocol.BackupInfo{{FileName: "backup.tar.gz", Path: "backup.tar.gz"}},
		},
		deleteBackupResult: protocol.DeleteBackupResultMessage{Success: true},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("n\n", func() error {
		return cmdBackupDelete("backup.tar.gz")
	})
	if err == nil {
		t.Fatal("cmdBackupDelete() error = nil, want cancellation")
	}
	if !strings.Contains(err.Error(), "delete cancelled") {
		t.Fatalf("cmdBackupDelete() error = %v, want cancellation", err)
	}
	if strings.Join(fake.requests, ",") != protocol.MsgTypeListBackups {
		t.Fatalf("requests = %v, want only list_backups", fake.requests)
	}
	if fake.deleteBackupRequest.ArchivePath != "" {
		t.Fatalf("delete request = %+v, want no delete request", fake.deleteBackupRequest)
	}
}

func TestBackupImportRejectsExtraArguments(t *testing.T) {
	err := cmdBackupImport([]string{"backup.tar.gz", "--not-a-flag"})
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("cmdBackupImport(extra args) error = %v, want usage", err)
	}
}
