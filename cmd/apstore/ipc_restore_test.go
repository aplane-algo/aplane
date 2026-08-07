// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/backup"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestCmdBackupImportRejectsInvalidSources(t *testing.T) {
	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	if err := cmdBackupImport([]string{filepath.Join(t.TempDir(), "backup.zip")}); err == nil {
		t.Fatal("cmdBackupImport(non-archive) error = nil, want extension rejection")
	} else if !strings.Contains(err.Error(), "must end in .tar.gz or .tgz") {
		t.Fatalf("cmdBackupImport(non-archive) error = %v, want extension context", err)
	}

	if err := cmdBackupImport([]string{filepath.Join(t.TempDir(), "missing.tar.gz")}); err == nil {
		t.Fatal("cmdBackupImport(missing) error = nil, want missing source rejection")
	} else if !strings.Contains(err.Error(), "backup source unavailable") {
		t.Fatalf("cmdBackupImport(missing) error = %v, want missing source context", err)
	}
}

func TestCmdBackupImportRejectsDuplicateBasename(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "restore-source.tar.gz")
	sealTestArchive(t, backupRoot, noderole.RoleSigner)
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport([]string{archivePath})
	}); err != nil {
		t.Fatalf("first cmdBackupImport() error = %v", err)
	}
	err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport([]string{archivePath})
	})
	if err == nil {
		t.Fatal("second cmdBackupImport() error = nil, want duplicate rejection")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second cmdBackupImport() error = %v, want duplicate context", err)
	}
}

func TestRestoreKeyRejectsWrongExportPassphrase(t *testing.T) {
	RegisterProviders()

	dataDirectory = t.TempDir()
	backupDir := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)

	encrypted, err := apcrypto.EncryptStandalone(keyJSON, []byte("correct-export-passphrase"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, address+".apb"), encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	keyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, bytes32(0x11)), []byte("wrong-export-passphrase"))
	if err == nil {
		t.Fatal("restoreKey() error = nil, want wrong passphrase failure")
	}
	if keyType != "" {
		t.Fatalf("restoreKey() keyType = %q, want empty on failure", keyType)
	}
	if !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("restoreKey() error = %v, want wrong passphrase context", err)
	}
}

func TestCmdBackupImportUsesManagedBackupDir(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "restore-source.tar.gz")
	sealTestArchive(t, backupRoot, noderole.RoleSigner)
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport([]string{archivePath})
	}); err != nil {
		t.Fatalf("cmdBackupImport() error = %v", err)
	}
	importedPath := filepath.Join(keystorePaths().IdentityBackupsDir(productIdentityID()), filepath.Base(archivePath))
	if _, err := os.Stat(importedPath); err != nil {
		t.Fatalf("imported archive stat error = %v", err)
	}
	items, err := backup.ListManagedBackups(keystorePaths(), productIdentityID())
	if err != nil {
		t.Fatalf("ListManagedBackups() error = %v", err)
	}
	if len(items) != 1 || items[0].FileName != filepath.Base(archivePath) {
		t.Fatalf("managed backups = %+v, want %s", items, filepath.Base(archivePath))
	}
	if len(items) != 1 || !items[0].Verified {
		t.Fatalf("managed backup import = %+v, want verified listed item", items)
	}
}

func TestCmdRestoreApplyManagedUsesDirectRestore(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		restoreResult: protocol.RestoreBackupResultMessage{
			Success:  true,
			Restored: []protocol.RestoreCredential{{Selector: "ADDR"}},
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{"restore-source.tar.gz", "--address", "ADDR", "--replace-existing"})
	}); err != nil {
		t.Fatalf("cmdRestoreApplyManaged() error = %v", err)
	}

	wantRequests := []string{protocol.MsgTypeRestoreBackup}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
	if fake.restoreRequest.ArchivePath != "restore-source.tar.gz" {
		t.Fatalf("restore archive = %q, want restore-source.tar.gz", fake.restoreRequest.ArchivePath)
	}
	if len(fake.restoreRequest.Addresses) != 1 || fake.restoreRequest.Addresses[0] != "ADDR" {
		t.Fatalf("restore addresses = %v, want [ADDR]", fake.restoreRequest.Addresses)
	}
	if !fake.restoreRequest.ReplaceExisting {
		t.Fatalf("restore request = %+v, want replace_existing", fake.restoreRequest)
	}
}

func TestCmdRestoreApplyManagedStopsWhenDirectRestoreFails(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		restoreResult: protocol.RestoreBackupResultMessage{
			Code:  protocol.ResultCodeRestoreFailed,
			Error: "bad backup",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{"restore-source.tar.gz"})
	})
	if err == nil {
		t.Fatal("cmdRestoreApplyManaged() error = nil, want recovery failure")
	}
	if !strings.Contains(err.Error(), "bad backup") {
		t.Fatalf("cmdRestoreApplyManaged() error = %v, want bad backup", err)
	}
	wantRequests := []string{protocol.MsgTypeRestoreBackup}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
}

func TestCmdRestoreApplyManagedStopsWhenBackupArchiveMissing(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		restoreResult: protocol.RestoreBackupResultMessage{
			Code:  "backup_not_found",
			Error: "backup archive not found",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{"missing.tar.gz"})
	})
	if err == nil {
		t.Fatal("cmdRestoreApplyManaged() error = nil, want missing backup archive failure")
	}
	if !strings.Contains(err.Error(), "backup archive not found") {
		t.Fatalf("cmdRestoreApplyManaged() error = %v, want missing archive context", err)
	}
	wantRequests := []string{protocol.MsgTypeRestoreBackup}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
}

func TestCmdRestoreRollbackUsesDirectOperation(t *testing.T) {
	rollbackFake := &fakeApstoreAdminRequester{
		rollbackRestoreResult: protocol.RollbackRestoreResultMessage{
			Success:      true,
			GenerationID: "gen-1-12345678",
		},
	}
	withFakeApstoreAdminClient(t, rollbackFake)
	if err := withTestStdin("y\n", func() error {
		return cmdRestoreRollback()
	}); err != nil {
		t.Fatalf("cmdRestoreRollback() error = %v", err)
	}
	if len(rollbackFake.requests) != 1 || rollbackFake.requests[0] != protocol.MsgTypeRollbackRestore {
		t.Fatalf("rollback requests = %v", rollbackFake.requests)
	}
}

func TestCmdRestoreManagedDispatchesReconcile(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		reconcileStoreResult: protocol.ReconcileStoreResultMessage{
			Success:      true,
			GenerationID: "gen-1-12345678",
			State:        "unlocked",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := cmdRestoreManaged([]string{"reconcile"}); err != nil {
		t.Fatalf("cmdRestoreManaged(reconcile) error = %v", err)
	}
	if got := strings.Join(fake.requests, ","); got != protocol.MsgTypeReconcileStore {
		t.Fatalf("requests = %q, want %q", got, protocol.MsgTypeReconcileStore)
	}
}

func TestFormatArchiveTime(t *testing.T) {
	if got := formatArchiveTime(1_700_000_000); got != "2023-11-14 22:13:20 UTC" {
		t.Fatalf("formatArchiveTime = %q, want a UTC timestamp", got)
	}
	// Absent packaging time renders as unknown rather than an epoch date.
	if got := formatArchiveTime(0); got != "unknown" {
		t.Fatalf("formatArchiveTime(0) = %q, want unknown", got)
	}
}
