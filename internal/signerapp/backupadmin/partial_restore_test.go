// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
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
	if preview.Code != "" || preview.Error != "" || len(preview.Keys) != 1 || len(preview.Errors) != 1 {
		t.Fatalf("PreviewRestore() = %+v", preview)
	}
	if key := preview.Keys[0]; key.Address != good || key.KeyType != "ed25519" || key.Error != "" || key.AlreadyExists {
		t.Fatalf("good preview key = %+v", key)
	}
	skipped := preview.Errors[0]
	if skipped.Address != "BAD" || !strings.HasPrefix(skipped.Error, badMemberReason) {
		t.Fatalf("preview skipped = %+v", preview.Errors)
	}

	result := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-mixed", ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"),
	})
	if !result.Success || result.Code != "" || result.Error != "" || result.ArchiveSHA256 == "" || result.GenerationID == "" ||
		len(result.Restored) != 1 || result.Restored[0].Selector != good || len(result.Identical) != 0 || len(result.Conflicts) != 0 ||
		len(result.Skipped) != 1 || result.Skipped[0] != (adminproto.RestoreSkipped{Selector: "BAD", Reason: skipped.Error}) {
		t.Fatalf("RestoreBackup(mixed) = %+v", result)
	}
}

// An import of an archive holding a key the node cannot admit is refused,
// naming how many restore would skip and the first.
func TestImportOfAMixedArchiveIsRefused(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeMixedValidityManagedArchive(t, paths)
	result := importArchiveForTest(t, directRestoreTestService(paths, ir), archivePath, "imported.tar.gz")
	if result.Success || !strings.HasPrefix(result.Error, "invalid backup contents: 1 of 2 credentials would be skipped by restore; first BAD: "+badMemberReason) {
		t.Fatalf("CommitBackupImport(mixed) = %+v", result)
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
