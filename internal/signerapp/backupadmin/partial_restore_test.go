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
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// badMemberReason is why the mixed archive's BAD member is refused.
const badMemberReason = "failed to parse backup credential: "

// The preview lists the BAD member among the keys with its error and again
// in errors; the whole-archive restore refuses with nothing restored.
func TestMixedArchivePreviewAndRestoreResults(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, good := writeMixedValidityManagedArchive(t, paths)
	service := directRestoreTestService(paths, ir)

	preview := service.PreviewRestore(adminproto.PreviewRestoreRequest{
		ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"),
	})
	if preview.Code != "" || preview.Error != "" || len(preview.Keys) != 2 || len(preview.Errors) != 1 {
		t.Fatalf("PreviewRestore() = %+v", preview)
	}
	byAddress := map[string]adminproto.RestoreKeyInfo{}
	for _, key := range preview.Keys {
		byAddress[key.Address] = key
	}
	if key := byAddress[good]; key.KeyType != "ed25519" || key.Error != "" || key.AlreadyExists {
		t.Fatalf("good preview key = %+v", key)
	}
	bad := byAddress["BAD"]
	if bad.KeyType != "" || !strings.HasPrefix(bad.Error, badMemberReason) {
		t.Fatalf("BAD preview key = %+v", bad)
	}
	if preview.Errors[0] != (adminproto.RestoreError{Address: "BAD", Error: bad.Error}) {
		t.Fatalf("preview errors = %+v", preview.Errors)
	}

	result := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-mixed", ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase"),
	})
	if result.Success || result.Code != protocol.ResultCodeRestoreFailed ||
		result.Error != "validate backup credential BAD: "+bad.Error ||
		result.ArchiveSHA256 != "" || result.GenerationID != "" ||
		len(result.Restored) != 0 || len(result.Identical) != 0 || len(result.Conflicts) != 0 || len(result.PoliciesRestored) != 0 {
		t.Fatalf("RestoreBackup(mixed) = %+v", result)
	}
}

// An import of an archive holding a key the node cannot admit is refused
// with the number of members that failed.
func TestImportOfAMixedArchiveIsRefused(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeMixedValidityManagedArchive(t, paths)
	result := importArchiveForTest(t, directRestoreTestService(paths, ir), archivePath, "imported.tar.gz")
	if result.Success || result.Error != "invalid backup contents: 1 of 2 credential files failed validation" {
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
