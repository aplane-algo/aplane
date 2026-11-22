// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	nativereg "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg"
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

// A key file written before a field was retired is a key the node cannot
// admit: the import accepts the archive and names it, and a restore from the
// import skips it and restores the rest. Each case is one such key file with
// the reason every step gives.
func TestImportThenRestoreSkipsARetiredKeyFile(t *testing.T) {
	nativereg.RegisterSigner()
	for _, tc := range []struct {
		name   string
		build  func(t *testing.T) (string, []byte)
		reason string
	}{
		{
			name:   "retired salt_counter",
			build:  func(t *testing.T) (string, []byte) { return keystest.RetiredSaltCounterLSigKeyJSON(t) },
			reason: `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "salt_counter"; restore or regenerate the key file using the current key schema`,
		},
		{
			name:   "native Falcon with pq_scheme and pq_address_salt",
			build:  func(t *testing.T) (string, []byte) { return preChangeNativeFalconKeyForTest(t, 0x91, true) },
			reason: preChangeNativeFalconReasonForTest,
		},
		{
			name:   "native Falcon without recovery entropy",
			build:  func(t *testing.T) (string, []byte) { return preChangeNativeFalconKeyForTest(t, 0x92, false) },
			reason: preChangeNativeFalconReasonForTest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			var reloads atomic.Int64
			ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
			service := directRestoreTestService(paths, ir)
			good, goodJSON := keystest.Ed25519KeyJSON(t)
			retired, retiredJSON := tc.build(t)
			want := []adminproto.RestoreSkipped{{Selector: retired, Reason: tc.reason}}

			archivePath := writeImportArchiveForTest(t, noderole.RoleSigner, map[string][]byte{good: goodJSON, retired: retiredJSON})
			imported := importArchiveForTest(t, service, archivePath, "retired.tar.gz")
			if !imported.Success || imported.Error != "" || !slices.Equal(imported.Skipped, want) {
				t.Fatalf("CommitBackupImport() = %+v, want skipped %+v", imported, want)
			}
			preview := service.PreviewRestore(adminproto.PreviewRestoreRequest{
				ArchivePath: "retired.tar.gz", ExportPassphrase: []byte("export-passphrase"),
			})
			if preview.Error != "" || len(preview.Keys) != 1 || preview.Keys[0].Address != good || !slices.Equal(preview.Skipped, want) {
				t.Fatalf("PreviewRestore() = %+v", preview)
			}
			restored := service.RestoreBackup(adminproto.RestoreBackupRequest{
				OperationID: "restore-retired", ArchivePath: "retired.tar.gz", ExportPassphrase: []byte("export-passphrase"),
			})
			if !restored.Success || len(restored.Restored) != 1 || restored.Restored[0].Selector != good || !slices.Equal(restored.Skipped, want) {
				t.Fatalf("RestoreBackup() = %+v", restored)
			}
			active := resolveAtomicTestGeneration(t, paths)
			if _, err := os.Stat(filepath.Join(active.KeysDir(), retired+".key")); !os.IsNotExist(err) {
				t.Fatalf("skipped credential was restored: %v", err)
			}
		})
	}
}

// preChangeNativeFalconReasonForTest is why this release refuses a native
// Falcon key file from before pq_scheme and pq_address_salt were dropped,
// with or without recovery entropy.
const preChangeNativeFalconReasonForTest = `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "pq_scheme"; restore or regenerate the key file using the current key schema`

// preChangeNativeFalconKeyForTest is a native Falcon key file in the shape
// written before pq_scheme and pq_address_salt were dropped, and its address.
func preChangeNativeFalconKeyForTest(t *testing.T, fill byte, recovery bool) (string, []byte) {
	t.Helper()
	address, keyJSON := keystest.NativeFalconKeyJSON(t, bytes.Repeat([]byte{fill}, 32))
	return address, keystest.PreChangeNativeFalconKeyJSON(t, keyJSON, recovery)
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
			if len(entry.Reason) > 1024 || !strings.HasSuffix(entry.Reason, "bytes)") {
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
	if len(listed) != maxReportedEntries || omitted != len(skipped)-maxReportedEntries || listed[0].Reason != reason {
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

// writeImportArchiveForTest seals members, each a selector and its
// plaintext, into an archive of role outside the managed directory.
func writeImportArchiveForTest(t *testing.T, role noderole.Role, members map[string][]byte) string {
	t.Helper()
	return writeArchiveForTest(t, role, members, filepath.Join(t.TempDir(), "import.tar.gz"))
}

// writeArchiveForTest seals members, each a selector and its plaintext,
// into an archive of role at archivePath.
func writeArchiveForTest(t *testing.T, role noderole.Role, members map[string][]byte, archivePath string) string {
	t.Helper()
	root := t.TempDir()
	apbDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(apbDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for selector, plaintext := range members {
		encrypted, err := crypto.EncryptStandalone(plaintext, []byte("export-passphrase"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(apbDir, selector+".apb"), encrypted, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := backup.WriteSealedManifest(root, role, time.Unix(1_700_000_000, 0), []byte("export-passphrase"), nil); err != nil {
		t.Fatal(err)
	}
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

// An import is checked against the importing node's role. One in which
// nothing would restore on this node is refused in the words a restore
// uses, naming what it would skip; a cosigner's backup on a signer is
// refused in one line that says so. Neither is called invalid. A
// hand-sealed archive of another role holding a key this node could hold
// gets the ordinary handling.
func TestImportIsCheckedAgainstThisNodesRole(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	service := directRestoreTestService(paths, ir)
	witness, witnessJSON := keystest.CosignerComponentFalcon1024KeyJSON(t, 0xcd)
	account, accountJSON := keystest.Ed25519KeyJSON(t)

	for _, tc := range []struct {
		name    string
		role    noderole.Role
		members map[string][]byte
		want    string
		skipped int
	}{
		{"nothing restorable", noderole.RoleSigner, map[string][]byte{"BAD": []byte(`{"format_version":3}`)},
			"nothing to restore: the backup's only credential is skipped: BAD: " + badMemberReason, 1},
		{"a cosigner's backup", noderole.RoleCosigner, map[string][]byte{witness: witnessJSON},
			"this is a cosigner backup; a signer node cannot restore it", 0},
	} {
		name := strings.ReplaceAll(tc.name, " ", "-") + ".tar.gz"
		result := importArchiveForTest(t, service, writeImportArchiveForTest(t, tc.role, tc.members), name)
		if result.Success || !strings.HasPrefix(result.Error, tc.want) || len(result.Skipped) != tc.skipped {
			t.Fatalf("%s: CommitBackupImport() = %+v, want %q", tc.name, result, tc.want)
		}
		if _, err := os.Lstat(filepath.Join(paths.ProductBackupsDir(), name)); !os.IsNotExist(err) {
			t.Fatalf("%s: refused import was published: %v", tc.name, err)
		}
	}

	crossRole := importArchiveForTest(t, service, writeImportArchiveForTest(t, noderole.RoleCosigner, map[string][]byte{account: accountJSON}), "cross-role.tar.gz")
	if !crossRole.Success || len(crossRole.Skipped) != 0 {
		t.Fatalf("CommitBackupImport(hand-sealed cross role) = %+v", crossRole)
	}
}

// withUnknownFieldForTest returns keyJSON with one more top-level field,
// which this release refuses to parse.
func withUnknownFieldForTest(t *testing.T, keyJSON []byte) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(keyJSON, &object); err != nil {
		t.Fatal(err)
	}
	object["extra"] = json.RawMessage("1")
	data, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A recovery restore whose damaged destination credential is in the backup
// but skipped there is refused, and names that credential with its skip
// reason and the damage found: a skipped copy repairs nothing. A healthy
// credential whose copy is skipped too is not named.
func TestRecoveryRestoreNamesASkippedRepair(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	service := directRestoreTestService(paths, ir)
	healthy, healthyJSON := keystest.Ed25519KeyJSON(t)
	damaged, damagedJSON := keystest.Ed25519KeyJSON(t)
	first := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-initial", ExportPassphrase: []byte("export-passphrase"),
		ArchivePath: writeArchiveForTest(t, noderole.RoleSigner, map[string][]byte{healthy: healthyJSON, damaged: damagedJSON},
			backup.BuildManagedArchivePath(paths, "initial")),
	})
	if !first.Success {
		t.Fatalf("initial restore = %+v", first)
	}
	before := resolveAtomicTestGeneration(t, paths)
	if err := os.WriteFile(filepath.Join(before.KeysDir(), damaged+".key"), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	ir.EnterRecovery(nil)

	fresh, freshJSON := keystest.Ed25519KeyJSON(t)
	result := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-skipped-repair", ExportPassphrase: []byte("export-passphrase"),
		ArchivePath: writeArchiveForTest(t, noderole.RoleSigner, map[string][]byte{
			healthy: withUnknownFieldForTest(t, healthyJSON), damaged: withUnknownFieldForTest(t, damagedJSON), fresh: freshJSON,
		}, backup.BuildManagedArchivePath(paths, "repair")),
	})
	want := "recovery restore refused: damaged destination credential " + damaged + " is in the backup, but its copy there is skipped (" + badMemberReason
	if result.Success || result.Code != protocol.ResultCodeRecoveryBlocked || !strings.HasPrefix(result.Error, want) ||
		!strings.Contains(result.Error, damaged+".key") || strings.Contains(result.Error, healthy) || len(result.Skipped) != 2 {
		t.Fatalf("RestoreBackup(skipped repair) = %+v, want prefix %q naming only %s", result, want, damaged)
	}
	if after := selectedAtomicTestGenerationID(t, paths); after != before.GenerationID() {
		t.Fatalf("store root after a refused recovery restore = %q, want %q", after, before.GenerationID())
	}
}

// A tar entry whose name is near the PAX limit is quoted bounded, so the
// preview, restore and import refusals each fit one admin frame. It needs
// no passphrase, so nothing about it is authenticated.
func TestLongEntryNameIsBoundedInRefusals(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	service := directRestoreTestService(paths, ir)
	archivePath := backup.BuildManagedArchivePath(paths, "long-name")
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	name := strings.Repeat("\x01", 900_000)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: 1, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	for _, closer := range []interface{ Close() error }{tw, gz, file} {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// Each refusal counts against the restore rate limit, so each request
	// gets a service of its own.
	preview := service.PreviewRestore(adminproto.PreviewRestoreRequest{ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase")})
	restored := directRestoreTestService(paths, ir).RestoreBackup(adminproto.RestoreBackupRequest{OperationID: "restore-long-name", ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase")})
	imported := importArchiveForTest(t, directRestoreTestService(paths, ir), archivePath, "long-name-import.tar.gz")
	for what, reply := range map[string]struct {
		text string
		msg  any
	}{
		"preview": {preview.Error, adminserver.ProtocolRestorePreviewMessage("p", preview)},
		"restore": {restored.Error, adminserver.ProtocolRestoreBackupResultMessage("r", restored)},
		"import":  {imported.Error, adminserver.ProtocolCommitBackupImportResultMessage("i", imported)},
	} {
		if !strings.Contains(reply.text, "…(900000 bytes)") || len(reply.text) > 4096 {
			t.Fatalf("%s refusal of %d bytes does not bound the name: %.200q", what, len(reply.text), reply.text)
		}
		if n := wireBytesForTest(t, reply.msg); n > 64*1024 {
			t.Fatalf("%s frame is %d bytes", what, n)
		}
	}
}

// A replace_existing restore of more keys than a result lists reports the
// first 64 restored and conflicting keys and counts the rest.
func TestReplacingRestoreBoundsItsLists(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	service := directRestoreTestService(paths, ir)
	original := map[string][]byte{}
	for range maxReportedEntries + 2 {
		selector, payload := keystest.Ed25519KeyJSON(t)
		original[selector] = payload
	}
	first := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-originals", ExportPassphrase: []byte("export-passphrase"),
		ArchivePath: writeArchiveForTest(t, noderole.RoleSigner, original, backup.BuildManagedArchivePath(paths, "originals")),
	})
	if !first.Success || len(first.Restored) != maxReportedEntries || first.RestoredOmitted != 2 {
		t.Fatalf("first restore: success %t, %d restored, %d omitted", first.Success, len(first.Restored), first.RestoredOmitted)
	}
	current := resolveAtomicTestGeneration(t, paths)
	for selector := range original {
		if err := os.WriteFile(filepath.Join(current.KeysDir(), selector+".key"), []byte("damaged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	replaced := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: "restore-replace", ExportPassphrase: []byte("export-passphrase"), ReplaceExisting: true,
		ArchivePath: writeArchiveForTest(t, noderole.RoleSigner, original, backup.BuildManagedArchivePath(paths, "replace")),
	})
	if !replaced.Success || len(replaced.Restored) != maxReportedEntries || replaced.RestoredOmitted != 2 ||
		len(replaced.Conflicts) != maxReportedEntries || replaced.ConflictsOmitted != 2 {
		t.Fatalf("replacing restore: success %t error %q, %d+%d restored, %d+%d conflicts", replaced.Success, replaced.Error,
			len(replaced.Restored), replaced.RestoredOmitted, len(replaced.Conflicts), replaced.ConflictsOmitted)
	}
}

// A replacing restore at the archive's entry cap still fits one frame: the
// restored and conflict lists hold 64 each, and the rest are counted.
func TestReplacingRestoreAtTheEntryCapFitsTheFrame(t *testing.T) {
	const keys = 16_398
	conflicts := make([]backup.RestoreConflict, keys)
	restored := make([]adminproto.RestoreCredential, keys)
	for i := range keys {
		selector := fmt.Sprintf("%058d", i)
		conflicts[i] = backup.RestoreConflict{
			Selector: selector, Category: "ed25519", KeyType: "ed25519",
			ExistingSHA256: strings.Repeat("ab", 32), Reason: "existing credential is unreadable: " + strings.Repeat("x", 4096),
		}
		restored[i] = adminproto.RestoreCredential{Selector: selector, Category: "ed25519", KeyType: "ed25519"}
	}
	result := adminproto.RestoreBackupResult{Success: true}
	result.Conflicts, result.ConflictsOmitted = projectRestoreConflicts(conflicts)
	result.Restored, result.RestoredOmitted = reported(restored)
	result.Identical, result.IdenticalOmitted = reported(restored)
	if len(result.Conflicts) != maxReportedEntries || result.ConflictsOmitted != keys-maxReportedEntries || len(result.Conflicts[0].Reason) > 1024 {
		t.Fatalf("conflicts: %d listed, %d omitted, reason %d bytes", len(result.Conflicts), result.ConflictsOmitted, len(result.Conflicts[0].Reason))
	}
	if n := wireBytesForTest(t, adminserver.ProtocolRestoreBackupResultMessage("r", result)); n > 128*1024 {
		t.Fatalf("restore frame is %d bytes", n)
	}
}

// An import that fails to extract names the entry by its path in the
// archive, never the daemon's validation directory, as restore does.
func TestImportExtractionErrorsNameArchivePaths(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	selector, payload := keystest.Ed25519KeyJSON(t)
	whole := writeImportArchiveForTest(t, noderole.RoleSigner, map[string][]byte{selector: payload})
	data, err := os.ReadFile(whole)
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(t.TempDir(), "truncated.tar.gz")
	if err := os.WriteFile(truncated, data[:len(data)*2/3], 0o600); err != nil {
		t.Fatal(err)
	}
	fileThenChild := filepath.Join(t.TempDir(), "file-then-child.tar.gz")
	file, err := os.Create(fileThenChild)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"a", "a/b"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	for _, closer := range []interface{ Close() error }{tw, gz, file} {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for archive, want := range map[string]string{
		truncated:     "invalid backup archive: failed to extract manifest.sealed: ",
		fileThenChild: "invalid backup archive: failed to create parent directory for a/b: ",
	} {
		result := importArchiveForTest(t, directRestoreTestService(paths, ir), archive, filepath.Base(archive))
		if result.Success || !strings.HasPrefix(result.Error, want) || strings.Contains(result.Error, "import-validation") || strings.Contains(result.Error, "<signer-store>") {
			t.Fatalf("CommitBackupImport(%s) error = %q, want prefix %q and no validation directory", filepath.Base(archive), result.Error, want)
		}
	}
}
