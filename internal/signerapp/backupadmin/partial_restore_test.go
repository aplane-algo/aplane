// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// badMemberReason is why the mixed archive's BAD member is refused.
const badMemberReason = "failed to parse backup credential: "

// The preview lists the BAD member as skipped, apart from the keys; the
// whole-archive restore restores the rest and reports BAD as skipped.
func TestMixedArchivePreviewAndRestoreResults(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, good := writeMixedValidityManagedArchive(t, paths)
	service := directRestoreTestService(paths, ir)

	preview := service.PreviewRestore(adminproto.PreviewRestoreRequest{
		ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"),
	})
	if preview.Code != "" || preview.Error != "" || len(preview.Keys) != 1 || len(preview.Skipped) != 1 {
		t.Fatalf("PreviewRestore() = %+v", preview)
	}
	if key := preview.Keys[0]; key.Address != good || key.KeyType != "ed25519" || key.AlreadyExists {
		t.Fatalf("good preview key = %+v", key)
	}
	skipped := preview.Skipped[0]
	if skipped.Selector != "BAD" || !strings.HasPrefix(skipped.Reason, badMemberReason) {
		t.Fatalf("preview skipped = %+v", preview.Skipped)
	}

	result := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-mixed", ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"),
	})
	if !result.Success || result.Code != "" || result.Error != "" || result.ArchiveSHA256 == "" || result.GenerationID == "" ||
		len(result.Restored) != 1 || result.Restored[0].Selector != good || len(result.Identical) != 0 || len(result.Conflicts) != 0 ||
		len(result.Skipped) != 1 || result.Skipped[0] != skipped {
		t.Fatalf("RestoreBackup(mixed) = %+v", result)
	}
}

// An archive holding a key the node cannot admit imports, naming that key
// with the reason, and a restore from the imported archive restores the rest
// and skips it.
func TestImportThenRestoreOfAMixedArchive(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, good := writeMixedValidityManagedArchive(t, paths)
	service := directRestoreTestService(paths, ir)

	imported := importArchiveForTest(t, service, archivePath, "imported.tar.gz")
	if !imported.Success || imported.Error != "" || imported.Backup.FileName != "imported.tar.gz" ||
		len(imported.Skipped) != 1 || imported.Skipped[0].Selector != "BAD" || !strings.HasPrefix(imported.Skipped[0].Reason, badMemberReason) {
		t.Fatalf("CommitBackupImport(mixed) = %+v", imported)
	}
	if _, err := os.Stat(filepath.Join(paths.ProductBackupsDir(), "imported.tar.gz")); err != nil {
		t.Fatalf("imported archive was not published: %v", err)
	}

	preview := service.PreviewRestore(adminproto.PreviewRestoreRequest{
		ArchivePath: "imported.tar.gz", ExportPassphrase: []byte("export-passphrase"),
	})
	if preview.Error != "" || len(preview.Keys) != 1 || preview.Keys[0].Address != good ||
		len(preview.Skipped) != 1 || preview.Skipped[0] != imported.Skipped[0] {
		t.Fatalf("PreviewRestore(imported) = %+v", preview)
	}
	restored := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-imported", ArchivePath: "imported.tar.gz", ExportPassphrase: []byte("export-passphrase"),
	})
	if !restored.Success || len(restored.Restored) != 1 || restored.Restored[0].Selector != good ||
		len(restored.Skipped) != 1 || restored.Skipped[0] != imported.Skipped[0] {
		t.Fatalf("RestoreBackup(imported) = %+v", restored)
	}
	active := resolveAtomicTestGeneration(t, paths)
	if _, err := os.Stat(filepath.Join(active.KeysDir(), good+".key")); err != nil {
		t.Fatalf("admitted credential was not restored: %v", err)
	}
}

// A damaged credential member still refuses the import, as it refuses a
// restore: the sealed manifest named its digest.
func TestImportOfADamagedMemberIsRefused(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	root := t.TempDir()
	apbDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(apbDir, 0o750); err != nil {
		t.Fatal(err)
	}
	selector, payload := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(payload)
	encrypted, err := crypto.EncryptStandalone(payload, []byte("another-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apbDir, selector+".apb"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backup.WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0), []byte("export-passphrase"), nil); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "damaged.tar.gz")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	result := importArchiveForTest(t, directRestoreTestService(paths, ir), archivePath, "damaged.tar.gz")
	want := "invalid backup contents: backup credential " + selector + ": decrypt backup file: "
	if result.Success || !strings.HasPrefix(result.Error, want) || len(result.Skipped) != 0 {
		t.Fatalf("CommitBackupImport(damaged) = %+v, want prefix %q", result, want)
	}
	if _, err := os.Lstat(filepath.Join(paths.ProductBackupsDir(), "damaged.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("damaged archive was published: %v", err)
	}
}

// importArchiveForTest uploads the archive at path as name and commits it.
func importArchiveForTest(t *testing.T, service Service, path, name string) adminproto.CommitBackupImportResult {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	checksum, size, err := backup.FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	begin := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: name})
	if !begin.Success {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	appendBackupImportBytes(t, service, begin.UploadID, data)
	return service.CommitBackupImport(adminproto.CommitBackupImportRequest{
		UploadID: begin.UploadID, FileName: name, ExpectedSize: size, ExpectedSHA256: checksum,
		ExportPassphrase: []byte("export-passphrase"),
	})
}
