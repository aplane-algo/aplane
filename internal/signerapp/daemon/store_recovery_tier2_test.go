// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

type recordingReloadAudit struct {
	mu       sync.Mutex
	reloads  []int
	rejected []string
}

func (a *recordingReloadAudit) LogKeyReload(keyCount int) {
	a.mu.Lock()
	a.reloads = append(a.reloads, keyCount)
	a.mu.Unlock()
}

func (a *recordingReloadAudit) LogKeyRejected(keyFile, reason string) {
	a.mu.Lock()
	a.rejected = append(a.rejected, keyFile+":"+reason)
	a.mu.Unlock()
}

func (a *recordingReloadAudit) reloadCounts() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]int, len(a.reloads))
	copy(out, a.reloads)
	return out
}

func drainStageWork(ir *productruntime.Runtime) {
	for len(ir.StageWork()) > 0 {
		<-ir.StageWork()
	}
}

func holdStoreMutation(t *testing.T, server *Signer) (release func()) {
	t.Helper()
	locked := make(chan struct{})
	unlock := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.withStoreMutation(func() error {
			close(locked)
			<-unlock
			return nil
		})
	}()
	select {
	case <-locked:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out acquiring store mutation lock")
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			close(unlock)
			<-done
		})
	}
	t.Cleanup(release)
	return release
}

// ChangeStorePassphrase reloads under store maintenance while locked, so
// FinishStoreMaintenance must wake stage work and emit NotifyKeysChanged on a
// successful republish, and ReloadWithPassphrase must audit LogKeyReload.
// A failed republish or racing lock must trigger neither wake nor notice.
func TestChangeStorePassphraseRepublishWakesStageWorkNotifiesAndAuditsReload(t *testing.T) {
	t.Run("successful republish", func(t *testing.T) {
		server, cleanup := setupTestSigner(t)
		defer cleanup()
		convertTestSignerToGenerational(t, server)
		ir := server.productRuntime()
		generateTestKey(t, server, "ed25519")

		audit := &recordingReloadAudit{}
		var notifiedMu sync.Mutex
		var notified []int
		opts := testProductBuildOptions(server)
		hooks := server.productBuildHooks()
		ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
			return signerstartup.Build(ir, opts, kr)
		}, productruntime.ReloadEffects{
			Audit: audit,
			NotifyKeysChanged: func(keyCount int) {
				notifiedMu.Lock()
				notified = append(notified, keyCount)
				notifiedMu.Unlock()
			},
			Info:           hooks.Info,
			Warn:           hooks.Warn,
			NodeFailClosed: hooks.NodeFailClosed,
		})
		drainStageWork(ir)

		result := server.adminServices().ChangeStorePassphrase(
			context.Background(),
			adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: testPassphrase,
				NewPassphrase:     []byte("new-republish-passphrase"),
			},
		)
		if !result.Success {
			t.Fatalf("ChangeStorePassphrase() = %+v", result)
		}
		if !ir.IsUnlocked() || ir.IsRecovery() {
			t.Fatalf("state = %s, want unlocked", ir.GetState())
		}
		select {
		case <-ir.StageWork():
		default:
			t.Fatal("FinishStoreMaintenance republish did not wake stage work")
		}
		notifiedMu.Lock()
		gotNotified := append([]int(nil), notified...)
		notifiedMu.Unlock()
		if len(gotNotified) != 1 || gotNotified[0] != 1 {
			t.Fatalf("NotifyKeysChanged calls = %v, want [1]", gotNotified)
		}
		if gotAudit := audit.reloadCounts(); len(gotAudit) != 1 || gotAudit[0] != 1 {
			t.Fatalf("Audit.LogKeyReload calls = %v, want [1]", gotAudit)
		}
	})

	t.Run("failed republish does neither", func(t *testing.T) {
		server, cleanup := setupTestSigner(t)
		defer cleanup()
		convertTestSignerToGenerational(t, server)
		ir := server.productRuntime()

		var notified atomic.Int32
		opts := testProductBuildOptions(server)
		hooks := server.productBuildHooks()
		ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
			return signerstartup.Build(ir, opts, kr)
		}, productruntime.ReloadEffects{
			Audit:             hooks.ReloadAuditLog,
			NotifyKeysChanged: func(int) { notified.Add(1) },
			Info:              hooks.Info,
			Warn:              hooks.Warn,
			NodeFailClosed:    hooks.NodeFailClosed,
		})
		drainStageWork(ir)

		if err := os.WriteFile(server.keyPaths.NodeRolePath(), []byte("role: cosigner\n"), 0o600); err != nil {
			t.Fatalf("tamper node role: %v", err)
		}
		result := server.adminServices().ChangeStorePassphrase(
			context.Background(),
			adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: testPassphrase,
				NewPassphrase:     []byte("new-failing-passphrase"),
			},
		)
		if result.Success {
			t.Fatalf("ChangeStorePassphrase() = %+v, want failure", result)
		}
		if len(ir.StageWork()) != 0 {
			t.Fatal("failed passphrase change woke stage work")
		}
		if notified.Load() != 0 {
			t.Fatalf("failed passphrase change fired NotifyKeysChanged %d times, want 0", notified.Load())
		}
	})

	t.Run("racing lock during maintenance does neither", func(t *testing.T) {
		server, cleanup := setupTestSigner(t)
		defer cleanup()
		ir := server.productRuntime()

		var notified atomic.Int32
		ir.SetBuildFunc(nil, productruntime.ReloadEffects{
			NotifyKeysChanged: func(int) { notified.Add(1) },
		})
		drainStageWork(ir)

		tok := ir.BeginStoreMaintenance()
		ir.Lock()
		if ir.FinishStoreMaintenance(tok, true) {
			t.Fatal("FinishStoreMaintenance() republished after a racing Lock")
		}
		if len(ir.StageWork()) != 0 {
			t.Fatal("refused FinishStoreMaintenance woke stage work")
		}
		if notified.Load() != 0 {
			t.Fatalf("refused FinishStoreMaintenance fired NotifyKeysChanged %d times, want 0", notified.Load())
		}
	})
}

func setupGenerationalBackupFixture(t *testing.T, deleteAfterBackup bool) (*Signer, string, func()) {
	t.Helper()
	server, cleanup := setupTestSigner(t)
	convertTestSignerToGenerational(t, server)
	addr := generateTestKey(t, server, "ed25519")
	archivePath := backupForTokenTest(t, server)
	if deleteAfterBackup {
		del := server.adminServices().keyApp().DeleteKey(context.Background(), adminproto.DeleteKeyRequest{Address: addr})
		if !del.Success {
			cleanup()
			t.Fatalf("DeleteKey(%s) = %+v", addr, del)
		}
	}
	return server, filepath.Base(archivePath), cleanup
}

// A restore started while unlocked can meet recovery entered while it waits
// for the store mutation lock. Sampling recovery inside the lock and deciding
// recovery exit from post-call state ensures the restore exits recovery (or
// reports recovery_blocked if rescan fails) rather than returning Success:true
// while the signer stays blocked in recovery.
func TestRestoreBackupEnteringRecoveryWhileWaitingForStoreLock(t *testing.T) {
	for _, tc := range []struct {
		name              string
		deleteAfterBackup bool
	}{
		{name: "committed restore exits recovery", deleteAfterBackup: true},
		{name: "idempotent no-op restore exits recovery", deleteAfterBackup: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, archiveName, cleanup := setupGenerationalBackupFixture(t, tc.deleteAfterBackup)
			defer cleanup()
			ir := server.productRuntime()
			if !ir.IsUnlocked() || ir.IsRecovery() {
				t.Fatalf("initial state = %s, want unlocked", ir.GetState())
			}

			release := holdStoreMutation(t, server)
			started := make(chan struct{})
			resultCh := make(chan adminproto.RestoreBackupResult, 1)
			go func() {
				close(started)
				resultCh <- server.adminServices().backupServices().RestoreBackup(adminproto.RestoreBackupRequest{
					OperationID:      "restore-lock-race-" + tc.name,
					ArchivePath:      archiveName,
					ExportPassphrase: []byte("export-passphrase"),
				})
			}()
			<-started
			// Wait briefly so RestoreBackup is past pre-lock checks and parked
			// on the store mutation lock while still unlocked.
			time.Sleep(30 * time.Millisecond)

			ir.EnterRecovery(errors.New("simulated watcher defect before lock release"))
			if !ir.IsRecovery() {
				t.Fatalf("state = %s, want recovery", ir.GetState())
			}
			release()

			var result adminproto.RestoreBackupResult
			select {
			case result = <-resultCh:
			case <-time.After(10 * time.Second):
				t.Fatal("RestoreBackup did not finish")
			}
			if !result.Success {
				t.Fatalf("RestoreBackup() = %+v, want success after exiting recovery", result)
			}
			if !ir.IsUnlocked() || ir.IsRecovery() {
				t.Fatalf("state after RestoreBackup = %s, want unlocked", ir.GetState())
			}
			if result.KeyCount != 1 {
				t.Fatalf("RestoreBackup KeyCount = %d, want 1", result.KeyCount)
			}
		})
	}

	t.Run("failed post-restore rescan reports recovery_blocked", func(t *testing.T) {
		server, archiveName, cleanup := setupGenerationalBackupFixture(t, true)
		defer cleanup()
		ir := server.productRuntime()

		var builds atomic.Int32
		wireBuildWith(server, func(bool) error {
			// Build 1 is FollowCommit inside RestoreBackup; build 2 is
			// exitRecoveryIfReconciled.
			if builds.Add(1) >= 2 {
				return errors.New("simulated post-restore rescan failure")
			}
			return nil
		})

		release := holdStoreMutation(t, server)
		started := make(chan struct{})
		resultCh := make(chan adminproto.RestoreBackupResult, 1)
		go func() {
			close(started)
			resultCh <- server.adminServices().backupServices().RestoreBackup(adminproto.RestoreBackupRequest{
				OperationID:      "restore-stays-in-recovery",
				ArchivePath:      archiveName,
				ExportPassphrase: []byte("export-passphrase"),
			})
		}()
		<-started
		time.Sleep(30 * time.Millisecond)
		ir.EnterRecovery(errors.New("simulated recovery before lock release"))
		release()

		var result adminproto.RestoreBackupResult
		select {
		case result = <-resultCh:
		case <-time.After(10 * time.Second):
			t.Fatal("RestoreBackup did not finish")
		}
		if result.Success || result.Code != protocol.ResultCodeRecoveryBlocked {
			t.Fatalf("RestoreBackup() = %+v, want Success=false Code=%s", result, protocol.ResultCodeRecoveryBlocked)
		}
		if !ir.IsRecovery() {
			t.Fatalf("state = %s, want recovery", ir.GetState())
		}
	})
}

// RollbackRestore started while unlocked can likewise meet recovery entered
// while it waits for the store mutation lock, and must exit recovery on a
// clean rescan or report recovery_blocked if rescan fails.
func TestRollbackRestoreEnteringRecoveryWhileWaitingForStoreLock(t *testing.T) {
	setupRestored := func(t *testing.T) (*Signer, func()) {
		t.Helper()
		server, archiveName, cleanup := setupGenerationalBackupFixture(t, true)
		res := server.adminServices().backupServices().RestoreBackup(adminproto.RestoreBackupRequest{
			OperationID:      "seed-restore-for-rollback",
			ArchivePath:      archiveName,
			ExportPassphrase: []byte("export-passphrase"),
		})
		if !res.Success {
			cleanup()
			t.Fatalf("seed RestoreBackup() = %+v", res)
		}
		return server, cleanup
	}

	t.Run("exits recovery on clean rescan", func(t *testing.T) {
		server, cleanup := setupRestored(t)
		defer cleanup()
		ir := server.productRuntime()

		release := holdStoreMutation(t, server)
		started := make(chan struct{})
		resultCh := make(chan adminproto.RollbackRestoreResult, 1)
		go func() {
			close(started)
			resultCh <- server.adminServices().backupServices().RollbackRestore(adminproto.RollbackRestoreRequest{
				OperationID: "rollback-lock-race",
			})
		}()
		<-started
		time.Sleep(30 * time.Millisecond)
		ir.EnterRecovery(errors.New("simulated watcher defect before rollback lock release"))
		release()

		var result adminproto.RollbackRestoreResult
		select {
		case result = <-resultCh:
		case <-time.After(10 * time.Second):
			t.Fatal("RollbackRestore did not finish")
		}
		if !result.Success {
			t.Fatalf("RollbackRestore() = %+v, want success after exiting recovery", result)
		}
		if !ir.IsUnlocked() || ir.IsRecovery() {
			t.Fatalf("state after RollbackRestore = %s, want unlocked", ir.GetState())
		}
	})

	t.Run("failed post-rollback rescan reports recovery_blocked", func(t *testing.T) {
		server, cleanup := setupRestored(t)
		defer cleanup()
		ir := server.productRuntime()

		var builds atomic.Int32
		wireBuildWith(server, func(bool) error {
			if builds.Add(1) >= 2 {
				return errors.New("simulated post-rollback rescan failure")
			}
			return nil
		})

		release := holdStoreMutation(t, server)
		started := make(chan struct{})
		resultCh := make(chan adminproto.RollbackRestoreResult, 1)
		go func() {
			close(started)
			resultCh <- server.adminServices().backupServices().RollbackRestore(adminproto.RollbackRestoreRequest{
				OperationID: "rollback-stays-in-recovery",
			})
		}()
		<-started
		time.Sleep(30 * time.Millisecond)
		ir.EnterRecovery(errors.New("simulated recovery before rollback lock release"))
		release()

		var result adminproto.RollbackRestoreResult
		select {
		case result = <-resultCh:
		case <-time.After(10 * time.Second):
			t.Fatal("RollbackRestore did not finish")
		}
		if result.Success || result.Code != protocol.ResultCodeRecoveryBlocked {
			t.Fatalf("RollbackRestore() = %+v, want Success=false Code=%s", result, protocol.ResultCodeRecoveryBlocked)
		}
		if !ir.IsRecovery() {
			t.Fatalf("state = %s, want recovery", ir.GetState())
		}
	})
}

// If another unlock promoted the signer out of recovery before the
// non-explicit recovery-exit rescan acquired the store mutation lock, the
// rescan must skip Reconcile rather than run a non-explicit reconcile on an
// unlocked signer.
func TestExitRecoveryRescanSkipsWhenAlreadyUnlocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	convertTestSignerToGenerational(t, server)
	ir := server.productRuntime()
	generateTestKey(t, server, "ed25519")

	var builds atomic.Int32
	wireBuildWith(server, func(bool) error {
		builds.Add(1)
		return errors.New("should not run build on already-unlocked non-explicit rescan")
	})

	report, err := server.adminServices().exitRecoveryIfReconciled(ir)
	if err != nil {
		t.Fatalf("exitRecoveryIfReconciled(unlocked) error = %v, want nil", err)
	}
	if report == nil || report.KeyCount != 1 {
		t.Fatalf("exitRecoveryIfReconciled(unlocked) report = %+v, want KeyCount=1", report)
	}
	if builds.Load() != 0 {
		t.Fatalf("non-explicit rescan ran %d build(s) on already-unlocked signer, want 0", builds.Load())
	}
	if !ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf("state = %s, want unlocked", ir.GetState())
	}
}
