// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package runtime

import (
	"errors"
	"sync/atomic"
	"testing"
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
