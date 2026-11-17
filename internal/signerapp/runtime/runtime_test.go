// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package runtime

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestLockInvokesOnLockOnlyForUnlockedTransition(t *testing.T) {
	rt := New()
	var lockCalls atomic.Int32
	rt.SetOnLock(func() {
		lockCalls.Add(1)
	})

	rt.Lock()
	if got := lockCalls.Load(); got != 0 {
		t.Fatalf("onLock calls while already locked = %d, want 0", got)
	}

	rt.SetUnlocked()
	rt.Lock()
	if got := lockCalls.Load(); got != 1 {
		t.Fatalf("onLock calls after unlocked->locked transition = %d, want 1", got)
	}

	rt.Lock()
	if got := lockCalls.Load(); got != 1 {
		t.Fatalf("onLock calls after second Lock() = %d, want 1", got)
	}
}

func TestTryUnlockFailureKeepsRuntimeLocked(t *testing.T) {
	rt := New()
	var unlockedCalls atomic.Int32

	ok, keyCount, errMsg := rt.TryUnlock(func() (int, error) {
		return 0, errors.New("unlock failed")
	}, func() {
		unlockedCalls.Add(1)
	})

	if ok {
		t.Fatal("TryUnlock() success = true, want false")
	}
	if keyCount != 0 {
		t.Fatalf("TryUnlock() keyCount = %d, want 0", keyCount)
	}
	if errMsg != "unlock failed" {
		t.Fatalf("TryUnlock() errMsg = %q, want %q", errMsg, "unlock failed")
	}
	if state := rt.GetState(); state != SignerStateLocked {
		t.Fatalf("state after failed unlock = %v, want %v", state, SignerStateLocked)
	}
	if got := unlockedCalls.Load(); got != 0 {
		t.Fatalf("onUnlocked calls after failed unlock = %d, want 0", got)
	}
}

func TestTryUnlockSuccessUnlocksAndCallsOnUnlocked(t *testing.T) {
	rt := New()
	var unlockedCalls atomic.Int32

	ok, keyCount, errMsg := rt.TryUnlock(func() (int, error) {
		return 7, nil
	}, func() {
		unlockedCalls.Add(1)
	})

	if !ok {
		t.Fatal("TryUnlock() success = false, want true")
	}
	if keyCount != 7 {
		t.Fatalf("TryUnlock() keyCount = %d, want 7", keyCount)
	}
	if errMsg != "" {
		t.Fatalf("TryUnlock() errMsg = %q, want empty string", errMsg)
	}
	if state := rt.GetState(); state != SignerStateUnlocked {
		t.Fatalf("state after successful unlock = %v, want %v", state, SignerStateUnlocked)
	}
	if got := unlockedCalls.Load(); got != 1 {
		t.Fatalf("onUnlocked calls after successful unlock = %d, want 1", got)
	}
}

// TestTryUnlockLosesToRacingLock pins the lock-wins semantics: a Lock that
// lands while the unlock function is running must leave the runtime locked,
// re-run the lock callback to destroy whatever the unlock loaded, and fail
// the unlock.
func TestTryUnlockLosesToRacingLock(t *testing.T) {
	r := New()
	lockCalls := 0
	r.SetOnLock(func() { lockCalls++ })
	r.SetUnlocked() // so the racing Lock takes the unlocked->locked path

	ok, _, errMsg := r.TryUnlock(func() (int, error) {
		r.Lock() // races the in-flight unlock
		return 3, nil
	}, nil)

	if ok {
		t.Fatal("TryUnlock succeeded despite racing Lock")
	}
	if errMsg == "" {
		t.Fatal("TryUnlock returned no error message")
	}
	if r.GetState() != SignerStateLocked {
		t.Fatalf("state = %v, want locked", r.GetState())
	}
	// Once for the racing Lock, once for the rollback of the loaded session.
	if lockCalls != 2 {
		t.Fatalf("lock callback ran %d times, want 2", lockCalls)
	}
}

// TestTryUnlockSucceedsWithoutRacingLock pins the happy path.
func TestTryUnlockSucceedsWithoutRacingLock(t *testing.T) {
	r := New()
	ok, keyCount, errMsg := r.TryUnlock(func() (int, error) { return 5, nil }, nil)
	if !ok || keyCount != 5 || errMsg != "" {
		t.Fatalf("TryUnlock = (%v, %d, %q), want (true, 5, \"\")", ok, keyCount, errMsg)
	}
	if r.GetState() != SignerStateUnlocked {
		t.Fatalf("state = %v, want unlocked", r.GetState())
	}
}

func TestMaintenanceClearsStateAndRepublishesOnlyOnMatchingToken(t *testing.T) {
	r := New()
	r.SetUnlocked()
	cleanups := 0
	r.SetOnLock(func() {
		cleanups++
	})

	token := r.BeginMaintenance()
	if r.IsUnlocked() {
		t.Fatal("runtime remained unlocked during maintenance")
	}
	if cleanups != 1 {
		t.Fatalf("maintenance cleanups = %d, want 1", cleanups)
	}
	if !r.FinishMaintenance(token, true) {
		t.Fatal("FinishMaintenance() refused current token")
	}
	if !r.IsUnlocked() {
		t.Fatal("runtime not republished after maintenance")
	}
}

func TestMaintenanceRepublishLosesToRacingLock(t *testing.T) {
	r := New()
	r.SetUnlocked()
	token := r.BeginMaintenance()

	// Lock increments the fence even though maintenance already made the
	// visible state locked. That explicit lock must prevent republish.
	r.Lock()
	if r.FinishMaintenance(token, true) {
		t.Fatal("FinishMaintenance() overrode a racing Lock")
	}
	if r.IsUnlocked() {
		t.Fatal("runtime unlocked despite racing Lock")
	}
}

func TestMaintenanceRejectsUnlockAndRecoveryWithoutRunningCallbacks(t *testing.T) {
	r := New()
	r.SetUnlocked()
	token := r.BeginMaintenance()
	unlockRan := false
	recoveryRan := false

	ok, _, errMsg := r.TryUnlock(func() (int, error) {
		unlockRan = true
		return 1, nil
	}, nil)
	if ok || errMsg != MaintenanceInProgressMessage || unlockRan {
		t.Fatalf(
			"TryUnlock during maintenance = (%v, %q, ran=%v)",
			ok,
			errMsg,
			unlockRan,
		)
	}
	recoveryOK, recoveryErr := r.TryRecovery(func() error {
		recoveryRan = true
		return nil
	})
	if recoveryOK || recoveryErr != MaintenanceInProgressMessage || recoveryRan {
		t.Fatalf(
			"TryRecovery during maintenance = (%v, %q, ran=%v)",
			recoveryOK,
			recoveryErr,
			recoveryRan,
		)
	}
	if r.FinishMaintenance(token, false) {
		t.Fatal("failed maintenance unexpectedly republished runtime")
	}
	if r.GetState() != SignerStateLocked {
		t.Fatalf("state after failed maintenance = %v, want locked", r.GetState())
	}
}

func TestInFlightUnlockLosesToRacingMaintenance(t *testing.T) {
	r := New()
	cleanups := 0
	r.SetOnLock(func() { cleanups++ })
	var token MaintenanceToken

	ok, _, errMsg := r.TryUnlock(func() (int, error) {
		token = r.BeginMaintenance()
		return 1, nil
	}, nil)
	if ok || errMsg != LockedDuringUnlockMessage {
		t.Fatalf("TryUnlock racing maintenance = (%v, %q)", ok, errMsg)
	}
	if r.GetState() != SignerStateLocked {
		t.Fatalf("state after racing maintenance = %v, want locked", r.GetState())
	}
	// BeginMaintenance clears the old session; the losing TryUnlock clears
	// whatever its callback may have loaded.
	if cleanups != 2 {
		t.Fatalf("maintenance race cleanups = %d, want 2", cleanups)
	}
	if !r.FinishMaintenance(token, true) {
		t.Fatal("successful maintenance could not republish after rejecting the racing unlock")
	}
}

func TestMaintenanceFailureForcesLockedState(t *testing.T) {
	r := New()
	r.SetUnlocked()
	token := r.BeginMaintenance()

	// Model the old defect directly: even if another path has managed to
	// publish Unlocked, a failed maintenance finish must force Locked.
	r.stateMu.Lock()
	r.state = SignerStateUnlocked
	r.stateMu.Unlock()

	if r.FinishMaintenance(token, false) {
		t.Fatal("failed maintenance unexpectedly republished runtime")
	}
	if r.GetState() != SignerStateLocked {
		t.Fatalf("state after failed maintenance = %v, want locked", r.GetState())
	}
}

func TestTryRecoveryBlocksSigningAndLockRunsCleanup(t *testing.T) {
	r := New()
	var lockCalls atomic.Int32
	r.SetOnLock(func() { lockCalls.Add(1) })
	ok, errMsg := r.TryRecovery(func() error { return nil })
	if !ok || errMsg != "" {
		t.Fatalf("TryRecovery() = (%v, %q)", ok, errMsg)
	}
	if !r.IsRecovery() || r.IsUnlocked() || r.GetState().String() != "recovery" {
		t.Fatalf("recovery state = %v unlocked=%v", r.GetState(), r.IsUnlocked())
	}
	r.Lock()
	if r.GetState() != SignerStateLocked || lockCalls.Load() != 1 {
		t.Fatalf("Lock() state=%v cleanup calls=%d", r.GetState(), lockCalls.Load())
	}
}

// TestLockGenerationAdvancesOnEveryLockTransition pins the property
// per-unlock state is keyed by: every Lock and BeginMaintenance advances
// the generation, an unlock leaves it unchanged, so two unlocked sessions
// never share one and a late observer of an earlier lock cannot mistake
// it for the current session.
func TestLockGenerationAdvancesOnEveryLockTransition(t *testing.T) {
	r := New()
	g0 := r.LockGeneration()
	if ok, _, _ := r.TryUnlock(func() (int, error) { return 1, nil }, nil); !ok {
		t.Fatal("unlock failed")
	}
	if r.LockGeneration() != g0 {
		t.Fatal("unlock changed the lock generation")
	}
	r.Lock()
	g1 := r.LockGeneration()
	if g1 != g0+1 {
		t.Fatalf("generation after lock = %d, want %d", g1, g0+1)
	}
	if ok, _, _ := r.TryUnlock(func() (int, error) { return 1, nil }, nil); !ok {
		t.Fatal("second unlock failed")
	}
	token := r.BeginMaintenance()
	if r.LockGeneration() != g1+1 {
		t.Fatalf("generation after maintenance = %d, want %d", r.LockGeneration(), g1+1)
	}
	r.FinishMaintenance(token, true)
	if r.LockGeneration() != g1+1 {
		t.Fatal("finishing maintenance changed the generation")
	}
}

// WhileGeneration runs its function only in the unlocked session it names,
// and a Lock that arrives while the function runs waits for it: nothing
// published under it can land after that session has ended.
func TestWhileGenerationRunsOnlyInItsSession(t *testing.T) {
	rt := New()
	ran := func(generation uint64) bool {
		return rt.WhileGeneration(generation, func() {})
	}
	if ran(rt.LockGeneration()) {
		t.Fatal("ran on a locked signer")
	}
	rt.SetUnlocked()
	session := rt.LockGeneration()
	if !ran(session) {
		t.Fatal("did not run in the current unlocked session")
	}

	inside, release, locked := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go rt.WhileGeneration(session, func() {
		close(inside)
		<-release
	})
	<-inside
	go func() {
		rt.Lock()
		close(locked)
	}()
	select {
	case <-locked:
		t.Fatal("a lock completed while the session's function was still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-locked

	if ran(session) {
		t.Fatal("ran in a session a lock had ended")
	}
	rt.SetUnlocked()
	if ran(session) {
		t.Fatal("ran for an earlier session after a new unlock")
	}
	if !ran(rt.LockGeneration()) {
		t.Fatal("did not run in the new session")
	}
	rt.SetRecovery()
	if ran(rt.LockGeneration()) {
		t.Fatal("ran in recovery")
	}
}

// Leaving the unlocked state for recovery ends the session: the generation
// moves, so work from that session finds it over even after a reconcile has
// unlocked the signer again. Nothing else that enters or leaves recovery
// moves it, and the unlock and maintenance fences are not disturbed.
func TestRecoveryEndsTheUnlockedSession(t *testing.T) {
	rt := New()
	var lockCalls atomic.Int32
	rt.SetOnLock(func() { lockCalls.Add(1) })

	// Locked to recovery is not the end of an unlocked session.
	before := rt.LockGeneration()
	rt.SetRecovery()
	if rt.LockGeneration() != before || !rt.IsRecovery() {
		t.Fatalf("locked to recovery: generation %d -> %d, state %v", before, rt.LockGeneration(), rt.GetState())
	}
	if !rt.PromoteRecoveryToUnlocked() || rt.LockGeneration() != before {
		t.Fatal("leaving recovery moved the generation or failed")
	}

	session := rt.LockGeneration()
	rt.SetRecovery()
	if rt.LockGeneration() == session {
		t.Fatal("unlocked to recovery left the session's generation in place")
	}
	if lockCalls.Load() != 0 {
		t.Fatal("recovery ran the on-lock cleanup; it has to keep the keyring")
	}
	inRecovery := rt.LockGeneration()
	rt.SetRecovery() // already there
	if rt.LockGeneration() != inRecovery {
		t.Fatal("recovery entered twice moved the generation twice")
	}
	if !rt.PromoteRecoveryToUnlocked() {
		t.Fatal("recovery did not promote")
	}
	if rt.WhileGeneration(session, func() {}) {
		t.Fatal("work from the session before the recovery ran in the session after it")
	}
	if !rt.WhileGeneration(rt.LockGeneration(), func() {}) {
		t.Fatal("the session after the recovery is not current")
	}

	// During maintenance SetRecovery does nothing, so the fence still closes.
	token := rt.BeginMaintenance()
	fenced := rt.LockGeneration()
	rt.SetRecovery()
	if rt.LockGeneration() != fenced {
		t.Fatal("recovery during maintenance moved the generation")
	}
	if !rt.FinishMaintenance(token, true) || !rt.IsUnlocked() {
		t.Fatalf("maintenance did not republish: state %v", rt.GetState())
	}

	// An unlock that runs while the signer is locked is not made to lose.
	rt.Lock()
	ok, _, msg := rt.TryUnlock(func() (int, error) { return 1, nil }, nil)
	if !ok {
		t.Fatalf("unlock after a lock: %s", msg)
	}
}

// TryRecovery is the other way into recovery, and it too can start from the
// unlocked state: an unlock request on a signer already unlocked, whose store
// then fails validation. It ends the session as SetRecovery does.
func TestTryRecoveryFromUnlockedEndsTheSession(t *testing.T) {
	rt := New()
	rt.SetUnlocked()
	session := rt.LockGeneration()
	if ok, msg := rt.TryRecovery(func() error { return nil }); !ok {
		t.Fatalf("TryRecovery: %s", msg)
	}
	if !rt.IsRecovery() || rt.LockGeneration() == session {
		t.Fatalf("state %v, generation %d (was %d); want recovery in a new generation", rt.GetState(), rt.LockGeneration(), session)
	}
	// From locked it ends nothing.
	rt.Lock()
	locked := rt.LockGeneration()
	if ok, msg := rt.TryRecovery(func() error { return nil }); !ok || rt.LockGeneration() != locked {
		t.Fatalf("TryRecovery from locked: ok %v (%s), generation %d -> %d", ok, msg, locked, rt.LockGeneration())
	}
}

// An entry into recovery destroys nothing, so an unlock that overlaps one has
// not lost to a lock: the lock's cleanup must not run and wipe the keyring
// recovery administration needs.
func TestUnlockOverlappingRecoveryDoesNotRunTheLockCleanup(t *testing.T) {
	rt := New()
	var lockCalls atomic.Int32
	rt.SetOnLock(func() { lockCalls.Add(1) })
	rt.SetUnlocked()
	ok, _, msg := rt.TryUnlock(func() (int, error) {
		rt.SetRecovery()
		return 1, nil
	}, nil)
	if msg == LockedDuringUnlockMessage || lockCalls.Load() != 0 {
		t.Fatalf("an unlock overlapping recovery was treated as losing to a lock: ok %v, %q, %d cleanup(s)", ok, msg, lockCalls.Load())
	}
}

// blockFirstCleanup installs an on-lock callback whose first call blocks until
// release is closed. entered is closed when that call begins, and returned
// counts the calls that have finished.
func blockFirstCleanup(rt *Runtime) (entered, release chan struct{}, returned *atomic.Int32) {
	entered = make(chan struct{})
	release = make(chan struct{})
	returned = &atomic.Int32{}
	var calls atomic.Int32
	rt.SetOnLock(func() {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		returned.Add(1)
	})
	return entered, release, returned
}

func expectBlocked(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s did not wait for the lock's cleanup", what)
	case <-time.After(50 * time.Millisecond):
	}
}

func expectDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not finish after the lock's cleanup returned", what)
	}
}

// A Lock moves the lock generation and then runs its cleanup outside the state
// mutex. An unlock that began in between used to read the new generation, pass
// the fence, and publish a session the cleanup was still about to destroy.
func TestTryUnlockWaitsForALockCleanupInProgress(t *testing.T) {
	rt := New()
	entered, release, returned := blockFirstCleanup(rt)
	rt.SetUnlocked()
	go rt.Lock()
	<-entered

	var cleanupsAtUnlock atomic.Int32
	cleanupsAtUnlock.Store(-1)
	var ok bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		ok, _, _ = rt.TryUnlock(func() (int, error) {
			cleanupsAtUnlock.Store(returned.Load())
			return 1, nil
		}, nil)
	}()

	expectBlocked(t, done, "TryUnlock")
	if rt.IsUnlocked() {
		t.Fatal("signer reports unlocked while the lock's cleanup is running")
	}
	close(release)
	expectDone(t, done, "TryUnlock")
	if !ok || !rt.IsUnlocked() {
		t.Fatalf("unlock after the cleanup: ok=%v unlocked=%v, want both true", ok, rt.IsUnlocked())
	}
	if got := cleanupsAtUnlock.Load(); got != 1 {
		t.Fatalf("cleanups finished when the unlock function ran = %d, want 1", got)
	}
}

func TestTryRecoveryWaitsForALockCleanupInProgress(t *testing.T) {
	rt := New()
	entered, release, returned := blockFirstCleanup(rt)
	rt.SetUnlocked()
	go rt.Lock()
	<-entered

	var cleanupsAtUnlock atomic.Int32
	cleanupsAtUnlock.Store(-1)
	var ok bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		ok, _ = rt.TryRecovery(func() error {
			cleanupsAtUnlock.Store(returned.Load())
			return nil
		})
	}()

	expectBlocked(t, done, "TryRecovery")
	if rt.IsRecovery() {
		t.Fatal("signer reports recovery while the lock's cleanup is running")
	}
	close(release)
	expectDone(t, done, "TryRecovery")
	if !ok || !rt.IsRecovery() {
		t.Fatalf("recovery after the cleanup: ok=%v recovery=%v, want both true", ok, rt.IsRecovery())
	}
	if got := cleanupsAtUnlock.Load(); got != 1 {
		t.Fatalf("cleanups finished when the unlock function ran = %d, want 1", got)
	}
}

// A maintenance that begins while an earlier Lock's cleanup is still running
// must not republish the signer as unlocked under that cleanup.
func TestFinishMaintenanceWaitsForAnEarlierLockCleanup(t *testing.T) {
	rt := New()
	entered, release, returned := blockFirstCleanup(rt)
	rt.SetUnlocked()
	go rt.Lock()
	<-entered

	token := rt.BeginMaintenance()
	var republished bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		republished = rt.FinishMaintenance(token, true)
	}()

	expectBlocked(t, done, "FinishMaintenance")
	if rt.IsUnlocked() {
		t.Fatal("signer reports unlocked while the lock's cleanup is running")
	}
	close(release)
	expectDone(t, done, "FinishMaintenance")
	if !republished || !rt.IsUnlocked() {
		t.Fatalf("after the cleanup: republished=%v unlocked=%v, want both true", republished, rt.IsUnlocked())
	}
	if got := returned.Load(); got != 2 {
		t.Fatalf("cleanups finished = %d, want 2", got)
	}
}

// An unlock that loses to a racing lock runs the cleanup itself. The next
// unlock waits for that one too.
func TestTryUnlockWaitsForALosingUnlocksCleanup(t *testing.T) {
	rt := New()
	rt.SetUnlocked()
	rt.Lock()
	entered, release, _ := blockFirstCleanup(rt)

	loser := make(chan struct{})
	go func() {
		defer close(loser)
		rt.TryUnlock(func() (int, error) {
			rt.Lock() // already locked: moves the generation, runs no cleanup
			return 1, nil
		}, nil)
	}()
	<-entered

	var ok bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		ok, _, _ = rt.TryUnlock(func() (int, error) { return 1, nil }, nil)
	}()
	expectBlocked(t, done, "TryUnlock")
	close(release)
	expectDone(t, done, "TryUnlock")
	<-loser
	if !ok || !rt.IsUnlocked() {
		t.Fatalf("unlock after the cleanup: ok=%v unlocked=%v, want both true", ok, rt.IsUnlocked())
	}
}
