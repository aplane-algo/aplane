// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package runtime

import (
	"sync/atomic"
	"testing"
)

// raceUnlock starts an attempt whose unlock function blocks until release is
// closed, and returns once the function is running. done is closed when the
// attempt returns.
func raceUnlock(attempt func(unlockFn func() error) (bool, string)) (release chan struct{}, done chan struct{}, result *struct {
	ok  bool
	msg string
}) {
	started := make(chan struct{})
	release, done = make(chan struct{}), make(chan struct{})
	result = &struct {
		ok  bool
		msg string
	}{}
	go func() {
		defer close(done)
		result.ok, result.msg = attempt(func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	return release, done, result
}

func tryUnlock(r *Runtime) func(func() error) (bool, string) {
	return func(unlockFn func() error) (bool, string) {
		ok, _, msg := r.TryUnlock(func() (int, error) { return 1, unlockFn() }, nil)
		return ok, msg
	}
}

// An unlock that a lock overtook, finishing after a newer unlock published a
// session, locks the runtime before it clears what it loaded, so the runtime
// never reads unlocked with its keys gone.
func TestLosingUnlockLocksASessionANewerUnlockPublished(t *testing.T) {
	r := New()
	var keysLoaded atomic.Bool
	r.SetOnLock(func() { keysLoaded.Store(false) })

	release, done, first := raceUnlock(tryUnlock(r))
	r.Lock() // a lock lands while the first unlock is still deriving
	if ok, _, msg := r.TryUnlock(func() (int, error) { keysLoaded.Store(true); return 1, nil }, nil); !ok {
		t.Fatalf("second unlock failed: %s", msg)
	}
	close(release)
	<-done

	if first.ok || first.msg != LockedDuringUnlockMessage {
		t.Fatalf("first unlock = (%v, %q), want it to lose", first.ok, first.msg)
	}
	if r.IsUnlocked() || keysLoaded.Load() {
		t.Fatalf("unlocked=%v keys=%v; want the runtime locked and its keys cleared", r.IsUnlocked(), keysLoaded.Load())
	}
}

// An unlock still in flight when an overtaken one loses loses too: the loser
// moved the generation, so the cleanup it runs cannot clear a session that
// unlock would publish.
func TestLosingUnlockFencesAnUnlockStillInFlight(t *testing.T) {
	r := New()
	var keysLoaded atomic.Bool
	var blockCleanup atomic.Bool
	cleanupStarted, finishCleanup := make(chan struct{}), make(chan struct{})
	r.SetOnLock(func() {
		if blockCleanup.CompareAndSwap(true, false) {
			close(cleanupStarted)
			<-finishCleanup
		}
		keysLoaded.Store(false)
	})

	releaseFirst, firstDone, first := raceUnlock(tryUnlock(r))
	r.Lock()
	releaseSecond, secondDone, second := raceUnlock(func(unlockFn func() error) (bool, string) {
		ok, _, msg := r.TryUnlock(func() (int, error) {
			err := unlockFn()
			keysLoaded.Store(true)
			return 1, err
		}, nil)
		return ok, msg
	})

	// The first unlock loses and its cleanup starts, then waits.
	blockCleanup.Store(true)
	close(releaseFirst)
	<-cleanupStarted
	// The second unlock loads its keys and finishes before that cleanup runs.
	close(releaseSecond)
	<-secondDone
	close(finishCleanup)
	<-firstDone

	if first.ok || second.ok || second.msg != LockedDuringUnlockMessage {
		t.Fatalf("first = %+v, second = %+v; want both to lose", *first, *second)
	}
	if r.IsUnlocked() || keysLoaded.Load() {
		t.Fatalf("unlocked=%v keys=%v; want the runtime locked and its keys cleared", r.IsUnlocked(), keysLoaded.Load())
	}
}

// A recovery attempt that a lock overtook locks a session a newer unlock
// published, as a losing unlock does.
func TestLosingRecoveryLocksASessionANewerUnlockPublished(t *testing.T) {
	r := New()
	var keysLoaded atomic.Bool
	r.SetOnLock(func() { keysLoaded.Store(false) })

	release, done, first := raceUnlock(r.TryRecovery)
	r.Lock()
	if ok, _, msg := r.TryUnlock(func() (int, error) { keysLoaded.Store(true); return 1, nil }, nil); !ok {
		t.Fatalf("unlock failed: %s", msg)
	}
	close(release)
	<-done

	if first.ok || first.msg != LockedDuringUnlockMessage {
		t.Fatalf("recovery = (%v, %q), want it to lose", first.ok, first.msg)
	}
	if r.IsUnlocked() || r.IsRecovery() || keysLoaded.Load() {
		t.Fatalf("unlocked=%v recovery=%v keys=%v; want the runtime locked and its keys cleared",
			r.IsUnlocked(), r.IsRecovery(), keysLoaded.Load())
	}
}
