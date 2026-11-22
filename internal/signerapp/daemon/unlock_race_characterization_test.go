// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
)

// An unlock request takes the store mutation lock twice, for its reconcile
// and for its load, and enters recovery in a third step with no lock held.
// The tests here land another connection's transition in those gaps. Each
// states a property the signer does not keep today and the reload redesign's
// one-hold unlock order is to make it keep.

// knownDefect records that property does not hold today. It fails once the
// property holds, so the change that makes it hold turns the call into a
// plain assertion.
func knownDefect(t *testing.T, holds bool, property string) {
	t.Helper()
	if holds {
		t.Fatalf("%s: this now holds. Replace knownDefect with an assertion of it.", property)
	}
	t.Logf("known defect, for the one-hold unlock order to close: %s", property)
}

// countPassphraseLoads counts the reloads with a passphrase, and runs each
// reload as wired.
func countPassphraseLoads(server *Signer) *atomic.Int32 {
	ir := server.productRuntime()
	opts, hooks := testProductBuildOptions(server), server.productBuildHooks()
	loads := &atomic.Int32{}
	ir.SetReloadFunc(func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if passphrase != nil {
			loads.Add(1)
		}
		return signerstartup.NewReloadService(ir, opts, hooks, session).Reload(passphrase)
	})
	return loads
}

// Race 1. An unlock begun in recovery reconciles under its first hold of the
// store mutation lock. A store change on another connection that ends in
// doubt after that hold, and before the unlock reads its session generations,
// enters recovery again. The unlock then loads and publishes: its fence sees
// no entry into recovery since its read. The signer is unlocked with no
// reconcile since the recovery that change entered, and signs. This is the
// one open race that does not fail closed.
func TestAnUnlockPublishesOverARecoveryEnteredAfterItsReconcile(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	address := heldAddress(t, server)
	server.config.UserAutoApprove = true
	ir.Config().SetUserAutoApprove(true)
	ir.SetRecovery() // the unlock begins in recovery

	var stateAtEntry signerruntime.SignerState
	entered := false
	gateStoreMutation(server, &gatedMutationLock{after: map[int32]func(){
		unlockAnswerCheck: func() {
			entered = true
			stateAtEntry = ir.GetState()
			ir.SetRecovery() // as a store change that ends in doubt does
		},
	}})
	success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
	if !entered {
		t.Fatal("the recovery was not entered: the unlock no longer releases the store mutation lock after its reconcile")
	}
	// The entry must land in the gap: after the reconcile, before the
	// publish. Once the request holds the lock from its reconcile to its
	// publish, the hook runs after the publish, the signer is unlocked
	// there, and this test no longer drives the race: the gap it needs is
	// gone, which is the fix. It is then to be replaced by a test of the
	// one-hold order, not turned into an assertion.
	if stateAtEntry != signerruntime.SignerStateRecovery {
		t.Fatalf("state when the unlock released the store mutation lock = %v, want recovery: the unlock published under its first hold, so there is no gap to land an entry into recovery in. Replace this test.", stateAtEntry)
	}
	if !success || errMsg != "" {
		t.Fatalf("UnlockIdentity() = (%v, %q, %q), want an answer without an error", success, errMsg, code)
	}

	knownDefect(t, ir.IsRecovery(), "a recovery entered after an unlock's reconcile is lifted only by a reconcile after it")
	// What the defect allows today: the signer signs.
	if got := signPaymentForTest(t, server, address); got != 200 {
		t.Fatalf("/sign = %d after the unlock published over the recovery, want 200 as the code stands", got)
	}
}

// Race 4. A lock that lands after an unlock attempt read its session
// generations and before its load has already won: the fence will refuse the
// attempt. The attempt loads all the same, publishing a keyring, a policy and
// key maps; its own cleanup then clears the keyring and the key maps, and the
// policy stays, as after any lock. The signer ends locked either way.
func TestAnUnlockThatHasLostToALockStillLoads(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	ir.Lock()
	loads := countPassphraseLoads(server)

	locked := false
	gateStoreMutation(server, &gatedMutationLock{before: map[int32]func(){
		unlockLoadCheck: func() {
			locked = true
			ir.Lock()
		},
	}})
	success, _, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase)
	if !locked {
		t.Fatal("the lock did not land: the unlock no longer takes the store mutation lock a second time for its load")
	}
	if success || errMsg != signerruntime.LockedDuringUnlockMessage {
		t.Fatalf("UnlockIdentity() = (%v, %q), want %q", success, errMsg, signerruntime.LockedDuringUnlockMessage)
	}
	if got := ir.GetState(); got != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v, want the lock to stand", got)
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("WithKeyring() = %v, want the keyring the attempt opened closed by its cleanup", err)
	}
	knownDefect(t, loads.Load() == 0, "an unlock attempt that has lost to a lock loads nothing")
}

// A lock that lands during an unlock request's reconcile, which then fails,
// is undone: the request enters recovery through a fence that reads the lock
// generation after the lock, so it moves the locked signer into recovery with
// an open keyring. Signing stays refused, but the operator's lock did not
// hold.
//
// The reconcile fails where it quarantines a generation the store root never
// selected; the lock lands at that write.
func TestALockDuringAnUnlocksFailedReconcileIsUndoneByItsRecovery(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	ir.SetRecovery()
	mintUnselectedGenerationForTest(t, server)

	locked := false
	lockDone := make(chan struct{})
	fsutil.TestHook = func(_ fsutil.HookOp, path string) error {
		if locked || !strings.Contains(path, "quarantine") {
			return nil
		}
		locked = true
		// On another goroutine, as a lock from another connection is: its
		// cleanup may wait for work this request holds. The state flips at
		// once, which is all this needs.
		go func() {
			ir.Lock()
			close(lockDone)
		}()
		waitForState(t, ir, signerruntime.SignerStateLocked)
		return errors.New("injected quarantine failure")
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
	fsutil.TestHook = nil
	if !locked {
		t.Fatal("the lock did not land: the reconcile quarantined nothing")
	}
	select {
	case <-lockDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the lock's cleanup did not complete")
	}
	t.Logf("UnlockIdentity() = (%v, %q, %q), state %v", success, errMsg, code, ir.GetState())

	knownDefect(t, ir.GetState() == signerruntime.SignerStateLocked,
		"a lock that lands during an unlock request stands, whichever way the request would have ended")
	if ir.GetState() != signerruntime.SignerStateRecovery {
		t.Fatalf("state = %v, want recovery as the code stands", ir.GetState())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("WithKeyring() = %v, want the keyring the recovery entry opened, as the code stands", err)
	}
}

// Nothing a lock's cleanup waits for waits for the store mutation lock. The
// one-hold unlock order waits for a cleanup in progress while it holds that
// lock, so a holder of key material that needed the lock to finish would
// deadlock the two. With the lock held here, as an unlock attempt will hold
// it:
//   - a key export waiting for the lock has not yet registered its key use,
//     so the cleanup does not wait for it;
//   - a key use in flight, as a rotating sign's, ends when the lock cancels
//     it;
//   - a keyring callback in flight ends without the lock.
//
// The lock's cleanup then completes with the store mutation lock still held.
func TestALocksCleanupCompletesWhileTheStoreMutationLockIsHeld(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	address := heldAddress(t, server)

	server.storeMutationLock.Lock()
	held := true
	release := func() {
		if held {
			held = false
			server.storeMutationLock.Unlock()
		}
	}
	defer release()

	// The export is parked on the store mutation lock before the lock
	// starts, so the cleanup meets it where a real one would be.
	exportWaiting := make(chan struct{}, 1)
	keys := server.restService().Deps.KeyAdmin
	keys.MutationLock = signallingLock{Locker: &server.storeMutationLock, waiting: exportWaiting}
	exported := make(chan adminproto.ExportKeyResult, 1)
	go func() {
		exported <- keys.ExportKey(context.Background(),
			adminproto.ExportKeyRequest{Address: address, Passphrase: append([]byte(nil), testPassphrase...)},
			func(adminproto.ExportKeyResult) error { return nil })
	}()
	select {
	case <-exportWaiting:
	case <-time.After(10 * time.Second):
		t.Fatal("the export did not reach the store mutation lock")
	}

	useCtx, endUse := ir.KeyUseContext(context.Background())
	if useCtx.Err() != nil {
		t.Fatal("no key use on an unlocked signer")
	}
	go func() {
		<-useCtx.Done()
		endUse()
	}()

	inCallback, endCallback := make(chan struct{}), make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		callbackDone <- ir.WithKeyring(func(*crypto.Keyring) error {
			close(inCallback)
			<-endCallback
			return nil
		})
	}()
	<-inCallback

	lockDone := make(chan struct{})
	go func() {
		ir.Lock()
		close(lockDone)
	}()
	waitForState(t, ir, signerruntime.SignerStateLocked)
	select {
	case <-lockDone:
		t.Fatal("the lock returned with a keyring callback in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(endCallback)
	select {
	case <-lockDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the lock's cleanup did not complete while the store mutation lock was held")
	}
	if err := <-callbackDone; err != nil {
		t.Fatalf("the keyring callback = %v", err)
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("WithKeyring() = %v after the cleanup, want the keyring closed", err)
	}

	// The export gets the store mutation lock, finds the signer locked, and
	// is refused.
	release()
	select {
	case result := <-exported:
		if result.Success {
			t.Fatalf("ExportKey() = %+v on a locked signer, want a refusal", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the export did not answer once the store mutation lock was released")
	}
}

// signallingLock is a store mutation lock that reports each Lock call before
// it waits.
type signallingLock struct {
	sync.Locker
	waiting chan<- struct{}
}

func (l signallingLock) Lock() {
	l.waiting <- struct{}{}
	l.Locker.Lock()
}

// waitForState waits until the signer is in state.
func waitForState(t *testing.T, ir *productruntime.Runtime, state signerruntime.SignerState) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for ir.GetState() != state {
		if time.Now().After(deadline) {
			t.Fatalf("state = %v, want %v", ir.GetState(), state)
		}
		runtime.Gosched()
	}
}
