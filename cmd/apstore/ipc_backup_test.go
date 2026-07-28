// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
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
		listBackupsResult: protocol.BackupsListMessage{
			Backups: []protocol.BackupInfo{{
				FileName: "aplane-backup-20260423-010203.tar.gz",
				Path:     managedPath,
				Size:     size,
				Checksum: checksum,
				Verified: true,
			}},
		},
	}
	withFakeApstoreAdminClient(t, fake)

	destinationDir := filepath.Join(t.TempDir(), "exports")
	if err := cmdBackupExport(checksum, destinationDir); err != nil {
		t.Fatalf("cmdBackupExport(checksum) error = %v", err)
	}
	if strings.Join(fake.requests, ",") != protocol.MsgTypeListBackups {
		t.Fatalf("requests = %v, want list_backups", fake.requests)
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

// TestConfirmUnverifiedTemplateProvenance covers the operator decision that
// replaces an unconditional import failure when the TEAL compiler is
// unreachable. The keys themselves already validated; only the bundled
// templates' correspondence to them is unproven.
func TestConfirmUnverifiedTemplateProvenance(t *testing.T) {
	report := &backup.VerifyReport{
		TotalFiles:                 2,
		ValidFiles:                 2,
		ProvenanceUnavailableFiles: 1,
		Results: []backup.VerifyResult{
			{FileName: "A.apb", Valid: true},
			{
				FileName:                      "B.apb",
				Valid:                         true,
				TemplateProvenanceUnavailable: true,
				TemplateProvenanceNote:        "bundled template provenance could not be verified: connection refused",
			},
		},
	}

	oldReader := stdinReader
	t.Cleanup(func() { stdinReader = oldReader })

	t.Run("declined", func(t *testing.T) {
		stdinReader = bufio.NewReader(strings.NewReader("n\n"))
		err := confirmUnverifiedTemplateProvenance(report, false)
		if err == nil {
			t.Fatal("declining the prompt still imported the backup")
		}
		if !strings.Contains(err.Error(), "cancelled") ||
			!strings.Contains(err.Error(), "--accept-unverified-template-provenance") {
			t.Fatalf("error = %v, want a cancellation naming the override flag", err)
		}
	})

	t.Run("accepted at the prompt", func(t *testing.T) {
		stdinReader = bufio.NewReader(strings.NewReader("y\n"))
		if err := confirmUnverifiedTemplateProvenance(report, false); err != nil {
			t.Fatalf("accepting the prompt failed the import: %v", err)
		}
	})

	t.Run("pre-accepted by flag without prompting", func(t *testing.T) {
		// No stdin available: a scripted run must not block on the prompt.
		stdinReader = bufio.NewReader(strings.NewReader(""))
		if err := confirmUnverifiedTemplateProvenance(report, true); err != nil {
			t.Fatalf("--accept-unverified-template-provenance failed the import: %v", err)
		}
	})
}

func TestBackupImportRejectsUnknownOption(t *testing.T) {
	err := cmdBackupImport([]string{"backup.tar.gz", "--not-a-flag"})
	if err == nil || !strings.Contains(err.Error(), "unknown backup import option") {
		t.Fatalf("cmdBackupImport(unknown option) error = %v, want rejection", err)
	}
}
