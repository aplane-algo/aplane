// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestDirectRestoreCommitsCredentialsAndIsPlaintextIdempotent(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, selector := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths)

	first := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-first",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !first.Success || len(first.Restored) != 1 || first.Restored[0].Selector != selector {
		t.Fatalf("RestoreBackup(first) = %+v", first)
	}
	current, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	manifest, err := genstore.ReadManifest(current)
	if err != nil {
		t.Fatalf("ReadManifest() error = %v", err)
	}
	if manifest.Operation != genstore.OperationCredentialRestore ||
		manifest.RestoreArchiveSHA256 != first.ArchiveSHA256 ||
		!manifest.RestoreRollbackEligible {
		t.Fatalf("restore manifest = %+v", manifest)
	}
	if _, err := os.Stat(filepath.Join(current.KeysDir(), selector+".key")); err != nil {
		t.Fatalf("restored credential stat error = %v", err)
	}
	keyTypeEntries, err := os.ReadDir(current.KeyTypeRecordsDir())
	if err != nil {
		t.Fatalf("ReadDir(keytypes) error = %v", err)
	}
	if len(keyTypeEntries) != 0 {
		t.Fatalf("restore created key-type state: %v", keyTypeEntries)
	}

	second := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-second",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !second.Success || len(second.Restored) != 0 || len(second.Identical) != 1 {
		t.Fatalf("RestoreBackup(idempotent) = %+v", second)
	}
	if second.GenerationID != first.GenerationID {
		t.Fatalf("idempotent generation = %s, want %s", second.GenerationID, first.GenerationID)
	}
}

func TestIdempotentRecoveryRestoreReloadsBeforePromotion(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths)
	first := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-initial",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !first.Success {
		t.Fatalf("initial restore = %+v", first)
	}
	before := reloads.Load()
	ir.SetRecovery()
	result := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-idempotent-recovery",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !result.Success || len(result.Identical) != 1 {
		t.Fatalf("idempotent recovery restore = %+v", result)
	}
	if reloads.Load() != before+1 {
		t.Fatalf("reload count = %d, want %d", reloads.Load(), before+1)
	}
}

func TestDirectRestoreTreatsUnreadableDestinationAsReplaceableConflict(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, selector := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths)

	first := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-initial",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !first.Success {
		t.Fatalf("initial restore = %+v", first)
	}
	current, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current.KeysDir(), selector+".key"), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}

	refused := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-refused",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if refused.Success || refused.Code != protocol.ResultCodeRestoreConflict || len(refused.Conflicts) != 1 {
		t.Fatalf("restore without replacement = %+v", refused)
	}
	repaired := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-repair",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
		ReplaceExisting:  true,
	})
	if !repaired.Success || len(repaired.Restored) != 1 {
		t.Fatalf("restore with replacement = %+v", repaired)
	}
}

func TestDirectRestoreRollbackCannotRollbackItself(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths)
	if result := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-for-rollback",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	}); !result.Success {
		t.Fatalf("RestoreBackup() = %+v", result)
	}

	rolledBack := service.RollbackRestore(ir, adminproto.RollbackRestoreRequest{OperationID: "rollback-one"})
	if !rolledBack.Success {
		t.Fatalf("RollbackRestore() = %+v", rolledBack)
	}
	manifest, err := genstore.ReadManifest(paths.GenerationPaths(auth.DefaultIdentityID, rolledBack.GenerationID))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Operation != genstore.OperationCredentialRestoreRollback {
		t.Fatalf("rollback operation = %q", manifest.Operation)
	}
	second := service.RollbackRestore(ir, adminproto.RollbackRestoreRequest{OperationID: "rollback-two"})
	if second.Success || second.Code != protocol.ResultCodeRestoreRollbackRefused {
		t.Fatalf("second RollbackRestore() = %+v", second)
	}
}

func TestDirectRestoreReportsVisibleDurabilityUnknownAsUncertain(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths)

	injected := errors.New("simulated identity-directory sync failure")
	identityDir := paths.IdentityDir(auth.DefaultIdentityID)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == identityDir {
			return injected
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	result := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-uncertain",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	fsutil.TestHook = nil

	if result.Success || result.Code != protocol.ResultCodeRestoreRollbackFailed || !result.CommitUncertain {
		t.Fatalf("RestoreBackup(durability unknown) = %+v", result)
	}
	if !ir.IsRecovery() {
		t.Fatal("durability-unknown restore did not enter recovery")
	}
	current, err := genstore.ReadCurrent(paths, auth.DefaultIdentityID)
	if err != nil || current != result.GenerationID {
		t.Fatalf("visible current = %q, %v; want uncertain generation %q", current, err, result.GenerationID)
	}
}

func TestDirectRollbackReportsVisibleDurabilityUnknownAndEntersRecovery(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths)
	restored := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-before-uncertain-rollback",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !restored.Success {
		t.Fatalf("RestoreBackup() = %+v", restored)
	}

	injected := errors.New("simulated rollback identity-directory sync failure")
	identityDir := paths.IdentityDir(auth.DefaultIdentityID)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == identityDir {
			return injected
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	result := service.RollbackRestore(ir, adminproto.RollbackRestoreRequest{
		OperationID: "rollback-uncertain",
	})
	fsutil.TestHook = nil

	if result.Success || result.Code != protocol.ResultCodeRestoreRollbackFailed || result.GenerationID == "" {
		t.Fatalf("RollbackRestore(durability unknown) = %+v", result)
	}
	if !ir.IsRecovery() {
		t.Fatal("durability-unknown rollback did not enter recovery")
	}
	current, err := genstore.ReadCurrent(paths, auth.DefaultIdentityID)
	if err != nil || current != result.GenerationID {
		t.Fatalf("visible current = %q, %v; want uncertain rollback generation %q", current, err, result.GenerationID)
	}
}

func TestRecoveryRestoreRejectsInvalidCurrentGenerationBeforeMint(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
	before, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(before.KeyTypeRecordsDir()); err != nil {
		t.Fatal(err)
	}
	ir.SetRecovery()

	result := directRestoreTestService(paths).RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-over-invalid-current",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if result.Success || result.Code != protocol.ResultCodeRestoreFailed {
		t.Fatalf("RestoreBackup(invalid recovery parent) = %+v", result)
	}
	if !strings.Contains(result.Error, "validate recovery-mode current generation") {
		t.Fatalf("restore error = %q, want recovery parent validation context", result.Error)
	}
	after, err := genstore.ReadCurrent(paths, auth.DefaultIdentityID)
	if err != nil || after != before.GenerationID() {
		t.Fatalf("CURRENT after rejected recovery restore = %q, %v; want %q", after, err, before.GenerationID())
	}
}

func TestDirectRollbackRefusesDivergedRestoreGeneration(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths)
	restored := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-before-divergence",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !restored.Success {
		t.Fatalf("RestoreBackup() = %+v", restored)
	}
	current, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFileDurable(filepath.Join(current.KeyTypeRecordsDir(), "post-restore.json"), []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}

	result := service.RollbackRestore(ir, adminproto.RollbackRestoreRequest{OperationID: "rollback-diverged"})
	if result.Success || result.Code != protocol.ResultCodeRestoreRollbackDiverged {
		t.Fatalf("RollbackRestore(diverged) = %+v", result)
	}
	if !strings.Contains(result.Error, "changed after credential restore") {
		t.Fatalf("rollback error = %q, want divergence context", result.Error)
	}
}

func TestDirectRestoreDuplicateSelectorsFailWithoutRateLimitingValidPassphrase(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, selector := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths)

	duplicate := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-duplicates",
		ArchivePath:      archivePath,
		Addresses:        []string{selector, selector},
		ExportPassphrase: []byte("export-passphrase"),
	})
	if duplicate.Success || !strings.Contains(duplicate.Error, "duplicate backup selector") {
		t.Fatalf("RestoreBackup(duplicates) = %+v", duplicate)
	}
	retry := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-after-duplicates",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !retry.Success || retry.Code == protocol.ResultCodeRestoreRateLimited {
		t.Fatalf("valid-passphrase retry = %+v", retry)
	}
}

func TestDirectRestoreOneBadCredentialWritesNothing(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, validSelector := writeMixedValidityManagedArchive(t, paths)
	before, err := genstore.ReadCurrent(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	result := directRestoreTestService(paths).RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      "restore-one-bad",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if result.Success || !strings.Contains(result.Error, "validate backup credential") {
		t.Fatalf("RestoreBackup(one bad) = %+v", result)
	}
	after, err := genstore.ReadCurrent(paths, auth.DefaultIdentityID)
	if err != nil || after != before {
		t.Fatalf("CURRENT after failed whole-archive validation = %q, %v; want %q", after, err, before)
	}
	active, err := genstore.ResolveActive(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(active.KeysDir(), validSelector+".key")); !os.IsNotExist(err) {
		t.Fatalf("valid credential was partially restored: %v", err)
	}
}

func directRestoreTestService(paths storepaths.Paths) Service {
	return Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
}

func writeCredentialOnlyManagedArchive(t *testing.T, paths storepaths.Paths) (string, string) {
	t.Helper()
	root := t.TempDir()
	apbDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(apbDir, 0o750); err != nil {
		t.Fatal(err)
	}
	selector, payload := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(payload)
	encrypted, err := crypto.EncryptStandalone(payload, []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apbDir, selector+".apb"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backup.WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(1_700_000_000, 0),
		[]byte("export-passphrase"),
	); err != nil {
		t.Fatal(err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, auth.DefaultIdentityID, "direct-restore")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	return archivePath, selector
}

func writeMixedValidityManagedArchive(t *testing.T, paths storepaths.Paths) (string, string) {
	t.Helper()
	root := t.TempDir()
	apbDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(apbDir, 0o750); err != nil {
		t.Fatal(err)
	}
	selector, payload := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(payload)
	encrypted, err := crypto.EncryptStandalone(payload, []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apbDir, selector+".apb"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	badEncrypted, err := crypto.EncryptStandalone([]byte(`{"format_version":3}`), []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apbDir, "BAD.apb"), badEncrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backup.WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0), []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, auth.DefaultIdentityID, "mixed-validity")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	return archivePath, selector
}
