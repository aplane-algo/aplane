// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
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

// writeOversizedReasonArchive writes a managed archive of one good key and
// eight members whose payload carries a field name of 600 KB, so each skip
// reason, which quotes it, is that long.
func writeOversizedReasonArchive(t *testing.T, paths storepaths.Paths) (string, string) {
	t.Helper()
	root := t.TempDir()
	apbDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(apbDir, 0o750); err != nil {
		t.Fatal(err)
	}
	seal := func(name string, plaintext []byte) {
		encrypted, err := crypto.EncryptStandalone(plaintext, []byte("export-passphrase"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(apbDir, name+".apb"), encrypted, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good, payload := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(payload)
	seal(good, payload)
	oversized := []byte(`{"` + strings.Repeat("x", 600_000) + `":1}`)
	for i := range 8 {
		seal(fmt.Sprintf("BAD%d", i), oversized)
	}
	if err := backup.WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0), []byte("export-passphrase"), nil); err != nil {
		t.Fatal(err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, "oversized-reasons")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	return archivePath, good
}

// wireBytesForTest is the size of msg as the admin protocol frames it.
func wireBytesForTest(t *testing.T, msg any) int {
	t.Helper()
	data, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	return len(data)
}

// Skip reasons as long as an archive can make them are cut, so the
// preview, the restore's reply and the import's reply each fit one admin
// frame and a committed restore never reads as a transport failure.
func TestSkipReasonsAreBoundedOnTheWire(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, good := writeOversizedReasonArchive(t, paths)
	service := directRestoreTestService(paths, ir)

	checkSkipped := func(what string, skipped []adminproto.RestoreSkipped, omitted int) {
		t.Helper()
		if len(skipped) != 8 || omitted != 0 {
			t.Fatalf("%s: %d skipped, %d omitted, want 8 and 0", what, len(skipped), omitted)
		}
		for _, entry := range skipped {
			if len(entry.Reason) > maxSkipReasonBytes || !strings.HasSuffix(entry.Reason, "bytes)") {
				t.Fatalf("%s: reason of %d bytes is not bounded: %.80q", what, len(entry.Reason), entry.Reason)
			}
		}
	}
	preview := service.PreviewRestore(adminproto.PreviewRestoreRequest{ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase")})
	checkSkipped("preview", preview.Skipped, preview.SkippedOmitted)
	if n := wireBytesForTest(t, adminserver.ProtocolRestorePreviewMessage("p", preview)); n > protocol.MaxAdminMessageBytes {
		t.Fatalf("preview frame is %d bytes", n)
	}
	restored := service.RestoreBackup(adminproto.RestoreBackupRequest{OperationID: "restore-oversized", ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase")})
	if !restored.Success || len(restored.Restored) != 1 || restored.Restored[0].Selector != good {
		t.Fatalf("RestoreBackup() = success %t restored %+v error %q", restored.Success, restored.Restored, restored.Error)
	}
	checkSkipped("restore", restored.Skipped, restored.SkippedOmitted)
	if n := wireBytesForTest(t, adminserver.ProtocolRestoreBackupResultMessage("r", restored)); n > protocol.MaxAdminMessageBytes {
		t.Fatalf("restore frame is %d bytes", n)
	}
	imported := importArchiveForTest(t, service, archivePath, "oversized.tar.gz")
	if !imported.Success {
		t.Fatalf("CommitBackupImport() error %q", imported.Error)
	}
	checkSkipped("import", imported.Skipped, imported.SkippedOmitted)
	if n := wireBytesForTest(t, adminserver.ProtocolCommitBackupImportResultMessage("i", imported)); n > protocol.MaxAdminMessageBytes {
		t.Fatalf("import frame is %d bytes", n)
	}
}

// An archive at the entry cap, every credential skipped with an ordinary
// reason, still fits: a result lists 64 skips and counts the rest.
func TestSkipListIsBoundedOnTheWire(t *testing.T) {
	reason := `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "salt_counter"; restore or regenerate the key file using the current key schema`
	skipped := make([]backup.SkippedEntry, 16_399)
	for i := range skipped {
		skipped[i] = backup.SkippedEntry{Selector: fmt.Sprintf("%058d", i), Reason: reason}
	}
	listed, omitted := projectSkippedEntries(skipped)
	if len(listed) != maxReportedSkips || omitted != len(skipped)-maxReportedSkips || listed[0].Reason != reason {
		t.Fatalf("projected %d, omitted %d", len(listed), omitted)
	}
	for what, msg := range map[string]any{
		"preview": adminserver.ProtocolRestorePreviewMessage("p", adminproto.RestorePreviewResult{Skipped: listed, SkippedOmitted: omitted}),
		"restore": adminserver.ProtocolRestoreBackupResultMessage("r", adminproto.RestoreBackupResult{Success: true, Skipped: listed, SkippedOmitted: omitted}),
		"import":  adminserver.ProtocolCommitBackupImportResultMessage("i", adminproto.CommitBackupImportResult{Success: true, Skipped: listed, SkippedOmitted: omitted}),
	} {
		if n := wireBytesForTest(t, msg); n > 64*1024 {
			t.Fatalf("%s frame is %d bytes", what, n)
		}
	}
}

// A cut keeps whole characters and says how long the text was.
func TestBoundSkipText(t *testing.T) {
	if got := boundSkipText("short", 10); got != "short" {
		t.Fatalf("boundSkipText(short) = %q", got)
	}
	long := strings.Repeat("é", 600)
	got := boundSkipText(long, 100)
	if len(got) > 100 || !utf8.ValidString(got) || !strings.HasSuffix(got, "…(1200 bytes)") {
		t.Fatalf("boundSkipText(long) = %q (%d bytes)", got, len(got))
	}
}
