// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// interruptedActivationFixture recovers one batch and interrupts its
// activation before the first active write, leaving a durable marker.
func interruptedActivationFixture(
	t *testing.T,
	service *Service,
	ir *identity.Runtime,
) (restoreID, reviewToken string) {
	t.Helper()
	paths := service.Deps.KeyPaths()
	archivePath, _ := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoverResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoverResult)
	}
	// The archive helper reuses one path per identity; free it so callers
	// can mint further batches.
	if err := os.Remove(archivePath); err != nil {
		t.Fatalf("remove consumed archive: %v", err)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	service.activationHook = func(point activationPoint) error {
		if point == activationBeforeApply {
			return errors.New("simulated crash before active writes")
		}
		return nil
	}
	interrupted := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	service.activationHook = nil
	if interrupted.Success {
		t.Fatalf("interrupted activation unexpectedly succeeded: %+v", interrupted)
	}
	if _, err := os.Stat(paths.RecoveredActivationDir(auth.DefaultIdentityID, recoverResult.RestoreID)); err != nil {
		t.Fatalf("activation marker missing after interruption: %v", err)
	}
	return recoverResult.RestoreID, review.ReviewToken
}

func TestActivateRecoveredRejectedWhileAnotherBatchIncomplete(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	markedID, _ := interruptedActivationFixture(t, &service, ir)

	// A second, unrelated batch.
	archivePath, _ := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	otherRecover := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !otherRecover.Success {
		t.Fatalf("RecoverBackup(other) = %+v", otherRecover)
	}
	otherReview := service.ReviewRecovered(ir, otherRecover.RestoreID)

	// Activation of the unrelated batch must be rejected while any marker
	// exists: rolling back the marked batch later must not be able to
	// destroy this batch's writes. [P1]
	blocked := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   otherRecover.RestoreID,
		ReviewToken: otherReview.ReviewToken,
	})
	if blocked.Success || blocked.Code != protocol.ResultCodeActivationIncomplete {
		t.Fatalf("ActivateRecovered(other while %s incomplete) = %+v, want code %s",
			markedID, blocked, protocol.ResultCodeActivationIncomplete)
	}

	// Rollback of a batch that holds no marker must fail without touching
	// anything.
	rollbackOther := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{
		RestoreID: otherRecover.RestoreID,
	})
	if rollbackOther.Success {
		t.Fatalf("RollbackRecovered(unmarked batch) = %+v, want failure", rollbackOther)
	}

	// Resolving the marked batch unblocks the other batch.
	resolved := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: markedID})
	if !resolved.Success {
		t.Fatalf("RollbackRecovered(marked) = %+v", resolved)
	}
	unblockedReview := service.ReviewRecovered(ir, otherRecover.RestoreID)
	unblocked := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   otherRecover.RestoreID,
		ReviewToken: unblockedReview.ReviewToken,
	})
	if !unblocked.Success {
		t.Fatalf("ActivateRecovered(after resolution) = %+v", unblocked)
	}
}

func TestRollbackLeavesUnownedActiveFilesInPlace(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	restoreID, _ := interruptedActivationFixture(t, &service, ir)

	// A file the activation does not own appears in the namespace (as a
	// pre-fix binary could have allowed via an unrelated later activation).
	keysDir := paths.KeysDir(auth.DefaultIdentityID)
	if err := os.MkdirAll(keysDir, 0o770); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	foreign := filepath.Join(keysDir, "unrelated-credential.key")
	if err := os.WriteFile(foreign, []byte("someone else's credential"), 0o660); err != nil {
		t.Fatalf("WriteFile(foreign) error = %v", err)
	}

	rollback := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: restoreID})
	if !rollback.Success {
		t.Fatalf("RollbackRecovered() = %+v", rollback)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("rollback deleted a file the activation did not own: %v", err)
	}
	if _, err := os.Stat(paths.RecoveredActivationDir(auth.DefaultIdentityID, restoreID)); !os.IsNotExist(err) {
		t.Fatalf("activation marker still present after rollback: err = %v", err)
	}
}

func TestFailedRollbackEntersRecoveryMode(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	archivePath, _ := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)

	// Every reload fails: activation fails after apply, and the automatic
	// rollback's own reload fails too, so reconciliation cannot complete.
	ir.SetReloadFunc(func(string, []byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, errors.New("persistent reload failure")
	})

	result := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	if result.Success || result.Code != protocol.ResultCodeRecoveredRollbackFailed {
		t.Fatalf("ActivateRecovered() = %+v, want code %s", result, protocol.ResultCodeRecoveredRollbackFailed)
	}
	// A failed rollback must block signing immediately, not at the next
	// unlock. [P1b]
	if !ir.IsRecovery() {
		t.Fatal("identity is not in recovery mode after a failed rollback")
	}
	if ir.IsUnlocked() {
		t.Fatal("identity still reports unlocked after a failed rollback")
	}
}

func TestCompletedActivationResumeFinishesCleanup(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	archivePath, _ := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)

	// Simulate a crash between recording completion and removing the batch:
	// publish an activation marker whose journal already says completed.
	journal := recovered.ActivationJournal{
		RestoreID:               recoverResult.RestoreID,
		State:                   recovered.ActivationCompleted,
		ReviewToken:             review.ReviewToken,
		DestinationPolicySHA256: review.DestinationPolicySHA256,
		DestinationApprovalMode: string(review.DestinationApprovalMode),
	}
	snapshot := recovered.RollbackSnapshot{
		RestoreID: recoverResult.RestoreID,
		Directories: []recovered.RollbackDirectory{
			{RelativePath: "keys", Owned: []string{}},
			{RelativePath: "keytypes", Owned: []string{}},
		},
	}
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		return recovered.CreateActivation(paths, auth.DefaultIdentityID, journal, snapshot, masterKey)
	}); err != nil {
		t.Fatalf("CreateActivation(completed) error = %v", err)
	}

	// Rollback must refuse: the activation succeeded, only cleanup remains.
	rollback := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{
		RestoreID: recoverResult.RestoreID,
	})
	if rollback.Success {
		t.Fatalf("RollbackRecovered(completed) = %+v, want refusal", rollback)
	}

	// Retrying the activation finishes the cleanup without re-applying.
	finished := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID: recoverResult.RestoreID,
	})
	if !finished.Success || !finished.Resumed {
		t.Fatalf("ActivateRecovered(completed) = %+v, want resumed success", finished)
	}
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, recoverResult.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("batch still present after completed-activation cleanup: err = %v", err)
	}
}

func TestActivationSyncsPrecedeRecoveryEvidenceRemoval(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)

	batchDir := paths.RecoveredBatchDir(auth.DefaultIdentityID, recoverResult.RestoreID)
	keysDir := paths.KeysDir(auth.DefaultIdentityID)
	type hookEvent struct {
		op           fsutil.HookOp
		path         string
		batchPresent bool
	}
	var events []hookEvent
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		_, statErr := os.Stat(batchDir)
		events = append(events, hookEvent{op: op, path: path, batchPresent: statErr == nil})
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	result := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	if !result.Success {
		t.Fatalf("ActivateRecovered() = %+v", result)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("activated key missing: %v", err)
	}

	// Every durability operation must happen while the recovery evidence
	// (the batch with its marker, journal, and snapshot) still exists:
	// syncs precede removals. [P1c]
	sawKeysDirSync := false
	for _, event := range events {
		if !event.batchPresent {
			t.Fatalf("durability op %s on %s ran after recovery evidence was removed", event.op, event.path)
		}
		if event.op == fsutil.OpDirSync && event.path == keysDir {
			sawKeysDirSync = true
		}
	}
	if !sawKeysDirSync {
		t.Fatal("no directory sync of the active keys namespace was observed before cleanup")
	}
	if len(events) == 0 {
		t.Fatal("no durability operations observed")
	}
}
