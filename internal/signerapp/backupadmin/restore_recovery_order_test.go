// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// recoveryAtReleaseDeps reports whether the runtime was already in recovery
// when the store mutation lock was released.
type recoveryAtReleaseDeps struct {
	Deps
	ir                *productruntime.Runtime
	recoveryAtRelease bool
}

func (d *recoveryAtReleaseDeps) WithStoreMutation(fn func() error) error {
	return d.Deps.WithStoreMutation(func() error {
		err := fn()
		d.recoveryAtRelease = d.ir.IsRecovery()
		return err
	})
}

// A restore that leaves the runtime behind the store root must enter recovery
// before the mutation lock is released: until then the runtime may still
// serve the superseded generation, and a key write taking the lock would
// land in it.
func TestRestoreEntersRecoveryBeforeReleasingTheLock(t *testing.T) {
	tests := []struct {
		name    string
		arrange func(t *testing.T, paths storepaths.Paths, ir *productruntime.Runtime)
	}{
		{"a commit whose durability is unknown", func(t *testing.T, paths storepaths.Paths, ir *productruntime.Runtime) {
			identityDir := paths.ProductDir()
			fsutil.TestHook = func(op fsutil.HookOp, path string) error {
				if op == fsutil.OpDirSync && path == identityDir {
					return errors.New("simulated identity-directory sync failure")
				}
				return nil
			}
			t.Cleanup(func() { fsutil.TestHook = nil })
		}},
		{"a reload that fails after the commit", func(t *testing.T, paths storepaths.Paths, ir *productruntime.Runtime) {
			ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
				return nil, errors.New("reload failed")
			})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			var reloads atomic.Int64
			ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
			archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
			service := directRestoreTestService(paths, ir)
			deps := &recoveryAtReleaseDeps{Deps: service.Deps, ir: ir}
			service.Deps = deps
			tt.arrange(t, paths, ir)

			result := service.RestoreBackup(adminproto.RestoreBackupRequest{
				OperationID:      "restore-recovery-order",
				ArchivePath:      archivePath,
				ExportPassphrase: []byte("export-passphrase"),
			})
			fsutil.TestHook = nil

			if result.Success || result.Code != protocol.ResultCodeRestoreRollbackFailed || result.GenerationID == "" {
				t.Fatalf("RestoreBackup() = %+v, want a committed restore that failed afterwards", result)
			}
			if !deps.recoveryAtRelease {
				t.Fatal("runtime entered recovery only after the store mutation lock was released")
			}
			if !ir.IsRecovery() {
				t.Fatal("runtime is not in recovery after the restore")
			}
		})
	}
}

// A restore or rollback passes the handler's state gate before it queues on
// the store mutation lock. A lock and a new unlock in that time leave the
// keyring open on a signer not yet published unlocked: the mutation once
// committed there, its failed reload's SetRecovery did nothing on the locked
// signer, and the unlock then published unlocked over a generation the
// runtime had not followed. Both now refuse under the lock unless the signer
// is unlocked or in recovery.
func TestRestoreAndRollbackOnASignerNotYetUnlockedAreRefused(t *testing.T) {
	const want = "signer is locked: keystore is locked"
	failReload := func(ir *productruntime.Runtime) {
		ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
			return nil, errors.New("reload failed")
		})
	}

	t.Run("restore", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		var reloads atomic.Int64
		initializeAtomicTestStore(t, paths, backupAdminTestPassphrase)
		ir := testUnpublishedBackupIdentityRuntime(t, paths, &reloads)
		archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
		before := selectedAtomicTestGenerationID(t, paths)
		failReload(ir)

		result := directRestoreTestService(paths, ir).RestoreBackup(adminproto.RestoreBackupRequest{
			OperationID:      "restore-during-unlock",
			ArchivePath:      archivePath,
			ExportPassphrase: []byte("export-passphrase"),
		})
		ir.SetUnlocked() // the unlock in flight publishes

		if after := selectedAtomicTestGenerationID(t, paths); after != before && ir.IsUnlocked() {
			t.Fatalf("the signer ended unlocked over generation %s, which its reload did not follow (restore answered %s)", after, result.Code)
		}
		if result.Success || result.Code != protocol.ResultCodeRestoreFailed || result.Error != want || result.GenerationID != "" {
			t.Fatalf("RestoreBackup() during an unlock = %+v, want %s: %s", result, protocol.ResultCodeRestoreFailed, want)
		}
	})

	t.Run("rollback", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		var reloads atomic.Int64
		restorer := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
		archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
		if result := directRestoreTestService(paths, restorer).RestoreBackup(adminproto.RestoreBackupRequest{
			OperationID:      "restore-for-rollback",
			ArchivePath:      archivePath,
			ExportPassphrase: []byte("export-passphrase"),
		}); !result.Success {
			t.Fatalf("RestoreBackup() = %+v", result)
		}
		ir := testUnpublishedBackupIdentityRuntime(t, paths, &reloads)
		before := selectedAtomicTestGenerationID(t, paths)
		failReload(ir)

		result := directRestoreTestService(paths, ir).RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback-during-unlock"})
		ir.SetUnlocked() // the unlock in flight publishes

		if after := selectedAtomicTestGenerationID(t, paths); after != before && ir.IsUnlocked() {
			t.Fatalf("the signer ended unlocked over generation %s, which its reload did not follow (rollback answered %s)", after, result.Code)
		}
		if result.Success || result.Code != protocol.ResultCodeRestoreRollbackRefused || result.Error != want || result.GenerationID != "" {
			t.Fatalf("RollbackRestore() during an unlock = %+v, want %s: %s", result, protocol.ResultCodeRestoreRollbackRefused, want)
		}
	})
}

// The restore limiter guards the archive passphrase against guessing, so it
// counts only attempts that tried the passphrase. A restore or preview
// refused for the signer's state, or for a keyring a lock closed, tried
// nothing; it once charged the limiter all the same, and the correct
// restore that followed was refused with restore_rate_limited.
func TestARefusalBeforeThePassphraseIsTriedDoesNotChargeTheRestoreLimiter(t *testing.T) {
	request := func(id, passphrase string) adminproto.RestoreBackupRequest {
		return adminproto.RestoreBackupRequest{OperationID: id, ExportPassphrase: []byte(passphrase)}
	}
	restore := func(t *testing.T, service Service, archivePath string, req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult {
		t.Helper()
		req.ArchivePath = archivePath
		return service.RestoreBackup(req)
	}

	t.Run("a restore refused for the signer's state", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		var reloads atomic.Int64
		initializeAtomicTestStore(t, paths, backupAdminTestPassphrase)
		ir := testUnpublishedBackupIdentityRuntime(t, paths, &reloads)
		archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
		service := directRestoreTestService(paths, ir)

		if refused := restore(t, service, archivePath, request("refused", "export-passphrase")); refused.Success || refused.Code != protocol.ResultCodeRestoreFailed {
			t.Fatalf("RestoreBackup() before the unlock = %+v, want a refusal", refused)
		}
		ir.SetUnlocked()
		if restored := restore(t, service, archivePath, request("restored", "export-passphrase")); !restored.Success {
			t.Fatalf("RestoreBackup() once unlocked = %+v, want success", restored)
		}
		// A wrong passphrase is a guess and still counts.
		if wrong := restore(t, service, archivePath, request("wrong", "wrong-passphrase")); wrong.Success {
			t.Fatalf("RestoreBackup(wrong passphrase) = %+v", wrong)
		}
		if limited := restore(t, service, archivePath, request("after-wrong", "export-passphrase")); limited.Code != protocol.ResultCodeRestoreRateLimited {
			t.Fatalf("RestoreBackup() after a wrong passphrase = %+v, want restore_rate_limited", limited)
		}
	})

	t.Run("a restore and a preview refused for a closed keyring", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		var reloads atomic.Int64
		ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
		archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
		service := directRestoreTestService(paths, ir)

		ir.KeyStore().ClearKeys() // a lock's cleanup, ahead of the state change
		if refused := restore(t, service, archivePath, request("closed", "export-passphrase")); refused.Success || refused.Code != protocol.ResultCodeRestoreFailed {
			t.Fatalf("RestoreBackup() with the keyring closed = %+v, want a refusal", refused)
		}
		if preview := service.PreviewRestore(adminproto.PreviewRestoreRequest{ArchivePath: archivePath, ExportPassphrase: []byte("export-passphrase")}); preview.Code != protocol.ResultCodeRestorePreviewFailed {
			t.Fatalf("PreviewRestore() with the keyring closed = %+v, want a refusal", preview)
		}
		if err := ir.KeyStore().Unlock(backupAdminTestPassphrase); err != nil {
			t.Fatal(err)
		}
		if restored := restore(t, service, archivePath, request("reopened", "export-passphrase")); !restored.Success {
			t.Fatalf("RestoreBackup() with the keyring open again = %+v, want success", restored)
		}
	})
}
