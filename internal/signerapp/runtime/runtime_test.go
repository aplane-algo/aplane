// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package runtime

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool, desc string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !cond() {
		t.Fatalf("condition not met within %s: %s", timeout, desc)
	}
}

func TestLockInvokesOnLockOnlyForUnlockedTransition(t *testing.T) {
	rt := New(time.Hour)
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
	rt := New(time.Hour)
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
	rt := New(time.Hour)
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

func TestResetSessionTimerLocksAfterInactivity(t *testing.T) {
	rt := New(30 * time.Millisecond)
	var lockCalls atomic.Int32
	rt.SetOnLock(func() {
		lockCalls.Add(1)
	})

	rt.SetUnlocked()
	rt.ResetSessionTimer()

	waitForCondition(t, 500*time.Millisecond, func() bool {
		return rt.GetState() == SignerStateLocked
	}, "runtime should auto-lock after inactivity")

	if got := lockCalls.Load(); got != 1 {
		t.Fatalf("onLock calls after inactivity timeout = %d, want 1", got)
	}
}

func TestResetSessionTimerRefreshesDeadline(t *testing.T) {
	rt := New(50 * time.Millisecond)
	var lockCalls atomic.Int32
	rt.SetOnLock(func() {
		lockCalls.Add(1)
	})

	rt.SetUnlocked()
	rt.ResetSessionTimer()

	time.Sleep(30 * time.Millisecond)
	rt.ResetSessionTimer()

	time.Sleep(30 * time.Millisecond)
	if state := rt.GetState(); state != SignerStateUnlocked {
		t.Fatalf("state after refreshed timer before second deadline = %v, want %v", state, SignerStateUnlocked)
	}

	waitForCondition(t, 500*time.Millisecond, func() bool {
		return rt.GetState() == SignerStateLocked
	}, "runtime should lock after refreshed deadline expires")

	if got := lockCalls.Load(); got != 1 {
		t.Fatalf("onLock calls after refreshed timer expires = %d, want 1", got)
	}
}

func TestStopSessionTimerPreventsAutoLock(t *testing.T) {
	rt := New(40 * time.Millisecond)
	var lockCalls atomic.Int32
	rt.SetOnLock(func() {
		lockCalls.Add(1)
	})

	rt.SetUnlocked()
	rt.ResetSessionTimer()
	rt.StopSessionTimer()

	time.Sleep(100 * time.Millisecond)

	if state := rt.GetState(); state != SignerStateUnlocked {
		t.Fatalf("state after StopSessionTimer() = %v, want %v", state, SignerStateUnlocked)
	}
	if got := lockCalls.Load(); got != 0 {
		t.Fatalf("onLock calls after StopSessionTimer() = %d, want 0", got)
	}
}

func TestSetSessionTimeoutNonPositiveDisablesAutoLock(t *testing.T) {
	rt := New(25 * time.Millisecond)
	var lockCalls atomic.Int32
	rt.SetOnLock(func() {
		lockCalls.Add(1)
	})

	rt.SetSessionTimeout(0)
	rt.SetUnlocked()
	rt.ResetSessionTimer()

	time.Sleep(80 * time.Millisecond)

	if state := rt.GetState(); state != SignerStateUnlocked {
		t.Fatalf("state with disabled session timeout = %v, want %v", state, SignerStateUnlocked)
	}
	if got := lockCalls.Load(); got != 0 {
		t.Fatalf("onLock calls with disabled session timeout = %d, want 0", got)
	}
}

func TestSetUnlockedDoesNotStartTimerOrInvokeCallbacks(t *testing.T) {
	rt := New(25 * time.Millisecond)
	var lockCalls atomic.Int32
	rt.SetOnLock(func() {
		lockCalls.Add(1)
	})

	rt.SetUnlocked()

	time.Sleep(80 * time.Millisecond)

	if state := rt.GetState(); state != SignerStateUnlocked {
		t.Fatalf("state after SetUnlocked() without timer reset = %v, want %v", state, SignerStateUnlocked)
	}
	if got := lockCalls.Load(); got != 0 {
		t.Fatalf("onLock calls after SetUnlocked() without timer reset = %d, want 0", got)
	}
}
