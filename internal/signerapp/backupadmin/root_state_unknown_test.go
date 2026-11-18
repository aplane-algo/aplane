// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"os"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// hideRootAfterCommit makes the next store root commit land and then fail
// with the root unreadable, which leaves its state unknown: the commit's
// directory sync moves the new root aside and fails. The returned function
// puts the root back.
func hideRootAfterCommit(t *testing.T, paths storepaths.Paths) func() {
	t.Helper()
	root, aside := paths.StoreRootPath(), paths.StoreRootPath()+".aside"
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op != fsutil.OpDirSync || path != paths.ProductDir() {
			return nil
		}
		fsutil.TestHook = nil
		if err := os.Rename(root, aside); err != nil {
			t.Error(err)
		}
		return errors.New("simulated identity-directory sync failure")
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	return func() {
		fsutil.TestHook = nil
		if err := os.Rename(aside, root); err != nil {
			t.Fatal(err)
		}
	}
}

// A restore whose root cannot be read back may have landed, so it enters
// recovery as an unconfirmed commit does, instead of reporting a failure
// before commit.
func TestDirectRestoreWithAnUnreadableRootEntersRecovery(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths, ir)

	restoreRoot := hideRootAfterCommit(t, paths)
	result := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID:      "restore-state-unknown",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	restoreRoot()

	if result.Success || result.Code != protocol.ResultCodeRestoreRollbackFailed || !result.CommitUncertain {
		t.Fatalf("RestoreBackup(root state unknown) = %+v", result)
	}
	if !ir.IsRecovery() {
		t.Fatal("a restore of unknown commit state did not enter recovery")
	}
	if got := selectedAtomicTestGenerationID(t, paths); result.GenerationID == "" || got != result.GenerationID {
		t.Fatalf("root selects %s, result names %q; want the commit that landed", got, result.GenerationID)
	}
}

// A rollback whose root cannot be read back enters recovery and reloads the
// same way.
func TestDirectRollbackWithAnUnreadableRootEntersRecovery(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
	service := directRestoreTestService(paths, ir)
	if restored := service.RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID:      "restore-before-state-unknown-rollback",
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	}); !restored.Success {
		t.Fatalf("RestoreBackup() = %+v", restored)
	}

	restoreRoot := hideRootAfterCommit(t, paths)
	reloadsBefore := reloads.Load()
	result := service.RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback-state-unknown"})
	restoreRoot()

	if result.Success || result.Code != protocol.ResultCodeRestoreRollbackFailed {
		t.Fatalf("RollbackRestore(root state unknown) = %+v", result)
	}
	if !ir.IsRecovery() {
		t.Fatal("a rollback of unknown commit state did not enter recovery")
	}
	if got := reloads.Load() - reloadsBefore; got != 1 {
		t.Fatalf("the rollback reloaded %d times, want 1", got)
	}
	if got := selectedAtomicTestGenerationID(t, paths); result.GenerationID == "" || got != result.GenerationID {
		t.Fatalf("root selects %s, result names %q; want the commit that landed", got, result.GenerationID)
	}
}
