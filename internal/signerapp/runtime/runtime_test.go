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
