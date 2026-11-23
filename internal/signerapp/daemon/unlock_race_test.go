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
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
)

// An unlock request holds the store mutation lock from its state read to its
// publish, and checks the lock generation it read at the start before its
// reconcile, before its load and at both of its ends. The tests here land a
// lock at those points, and check what the request leaves.

// countPassphraseLoads counts the reloads with a passphrase, and runs each
// reload as wired.
func countPassphraseLoads(server *Signer) *atomic.Int32 {
	_, fromPassphrase := countBuilds(server)
	return fromPassphrase
}

// lockAtTheQuarantine lands a lock, from another goroutine as one from
// another connection is, when the unlock's reconcile first writes into the
// quarantine, and returns fail from that write. The quarantine is of a
// generation the store root never selected. It returns a channel closed once
// the lock's cleanup has completed.
func lockAtTheQuarantine(t *testing.T, server *Signer, fail error) (lockDone <-chan struct{}, landed func() bool) {
	t.Helper()
	ir := server.productRuntime()
	mintUnselectedGenerationForTest(t, server)
	done := make(chan struct{})
	locked := false
	fsutil.TestHook = func(_ fsutil.HookOp, path string) error {
		if locked || !strings.Contains(path, "quarantine") {
			return nil
		}
		locked = true
		go func() {
			ir.Lock()
			close(done)
		}()
		waitForState(t, ir, signerruntime.SignerStateLocked)
		return fail
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	return done, func() bool { return locked }
}

// requireLockStood checks what an unlock request a lock overtook leaves: it
// answered that the signer locked, and the signer is locked with no keyring,
// once the lock's cleanup has completed.
func requireLockStood(t *testing.T, server *Signer, lockDone <-chan struct{}, success bool, errMsg string) {
	t.Helper()
	ir := server.productRuntime()
	select {
	case <-lockDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the lock's cleanup did not complete")
	}
	if success || errMsg != signerruntime.ErrLockedDuringUnlock.Error() {
		t.Fatalf("UnlockIdentity() = (%v, %q), want %q", success, errMsg, signerruntime.ErrLockedDuringUnlock)
	}
	if got := ir.GetState(); got != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v, want the lock to stand", got)
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("WithKeyring() = %v, want no keyring", err)
	}
}

// An unlock request that a lock overtook during its reconcile loads nothing:
// it checks the lock generation before its load. It once loaded all the
// same, publishing a keyring, a policy and key maps for its own cleanup to
// clear.
func TestAnUnlockThatHasLostToALockLoadsNothing(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	ir.Lock()
	loads := countPassphraseLoads(server)
	lockDone, landed := lockAtTheQuarantine(t, server, nil)

	success, _, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase)
	fsutil.TestHook = nil
	if !landed() {
		t.Fatal("the lock did not land: the reconcile quarantined nothing")
	}
	requireLockStood(t, server, lockDone, success, errMsg)
	if got := loads.Load(); got != 0 {
		t.Fatalf("the request loaded %d time(s) after it lost to a lock, want none", got)
	}
}

// A lock that lands during an unlock request's reconcile, which then fails,
// stands: the request enters no recovery. It once entered recovery through a
// fence that read the lock generation after the lock, moving the locked
// signer into recovery with an open keyring.
func TestALockDuringAnUnlocksFailedReconcileStands(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	ir.EnterRecovery(nil)
	lockDone, landed := lockAtTheQuarantine(t, server, errors.New("injected quarantine failure"))

	success, _, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase)
	fsutil.TestHook = nil
	if !landed() {
		t.Fatal("the lock did not land: the reconcile quarantined nothing")
	}
	requireLockStood(t, server, lockDone, success, errMsg)
}

// An unlock request waits for a lock's cleanup in progress while it holds the
// store mutation lock, and then completes: nothing the cleanup waits for
// waits for that lock. Here the cleanup waits for a key use, and an admin
// operation queues on the store mutation lock behind the request.
func TestAnUnlockWaitsForALocksCleanupUnderTheStoreMutationLock(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()

	useCtx, endUse := ir.KeyUseContext(context.Background())
	if useCtx.Err() != nil {
		t.Fatal("no key use on an unlocked signer")
	}
	lockDone := make(chan struct{})
	go func() {
		ir.Lock()
		close(lockDone)
	}()
	<-useCtx.Done() // the lock's cleanup has cancelled the key use and waits for it

	unlockWaiting := make(chan struct{}, 1)
	gateStoreMutation(server, &gatedMutationLock{after: map[int32]func(){}, before: map[int32]func(){
		unlockHold: func() { unlockWaiting <- struct{}{} },
	}})
	type answer struct {
		success bool
		errMsg  string
	}
	unlocked := make(chan answer, 1)
	go func() {
		success, _, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase)
		unlocked <- answer{success, errMsg}
	}()
	<-unlockWaiting
	adminDone := make(chan error, 1)
	go func() {
		adminDone <- server.adminServices().withStoreMutation(func() error { return nil })
	}()

	select {
	case <-unlocked:
		t.Fatal("the unlock completed while the lock's cleanup was still waiting")
	case <-time.After(100 * time.Millisecond):
	}
	endUse()
	for name, done := range map[string]<-chan struct{}{"the lock": lockDone} {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not complete", name)
		}
	}
	select {
	case got := <-unlocked:
		if !got.success || got.errMsg != "" {
			t.Fatalf("UnlockIdentity() = %+v after the cleanup, want a success", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the unlock did not complete after the lock's cleanup")
	}
	select {
	case err := <-adminDone:
		if err != nil {
			t.Fatalf("the admin operation = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the admin operation did not get the store mutation lock")
	}
	if !ir.IsUnlocked() {
		t.Fatalf("state = %v, want unlocked", ir.GetState())
	}
}

// An unlock that arrives during a passphrase change waits for it, since the
// change holds the store mutation lock throughout, and then meets the new
// store root: the old passphrase is refused and the new one answers.
func TestAnUnlockDuringAPassphraseChangeWaitsForIt(t *testing.T) {
	server := characterizedSigner(t)
	convertTestSignerToGenerational(t, server)
	newPassphrase := []byte("new-admin-passphrase")

	unlockWaiting := make(chan struct{})
	gateStoreMutation(server, &gatedMutationLock{before: map[int32]func(){
		unlockHold: func() { close(unlockWaiting) },
	}})
	type answer struct {
		success      bool
		errMsg, code string
	}
	unlocked := make(chan answer, 1)
	started := false
	identityDir := server.keyPaths.ProductDir()
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if started || op != fsutil.OpRename || !strings.HasPrefix(path, identityDir) {
			return nil
		}
		started = true
		go func() {
			success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
			unlocked <- answer{success, errMsg, code}
		}()
		<-unlockWaiting // it waits on the lock the change holds
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	changed := server.adminServices().ChangeStorePassphrase(context.Background(), adminproto.ChangeStorePassphraseRequest{
		CurrentPassphrase: testPassphrase, NewPassphrase: newPassphrase,
	})
	fsutil.TestHook = nil
	if !changed.Success {
		t.Fatalf("ChangeStorePassphrase() = %+v", changed)
	}
	if !started {
		t.Fatal("the unlock did not arrive during the change")
	}
	if got := <-unlocked; got.success || got.code != protocol.ErrCodeInvalidPassphrase {
		t.Fatalf("UnlockIdentity(old passphrase) = %+v after the change, want invalid_passphrase", got)
	}
	if success, _, errMsg, code := server.adminServices().UnlockIdentity(newPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(new passphrase) = (%v, %q, %q), want a success", success, errMsg, code)
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
