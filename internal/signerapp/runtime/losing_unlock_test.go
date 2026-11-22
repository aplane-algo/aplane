// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package runtime

import (
	"errors"
	"sync/atomic"
	"testing"
)

// raceUnlock starts an attempt whose unlock function blocks until release is
// closed, and returns once the function is running. done is closed when the
// attempt returns.
func raceUnlock(attempt func(unlockFn func() error) error) (release chan struct{}, done chan struct{}, result *struct {
	err error
}) {
	started := make(chan struct{})
	release, done = make(chan struct{}), make(chan struct{})
	result = &struct {
		err error
	}{}
	go func() {
		defer close(done)
		result.err = attempt(func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	return release, done, result
}

func tryUnlock(r *Runtime) func(func() error) error {
	return func(unlockFn func() error) error {
		_, err := r.TryUnlock(func() (int, error) { return 1, unlockFn() }, nil)
		return err
	}
}

// An unlock that a lock overtook, finishing after a newer unlock published a
// session, locks the runtime before it clears what it loaded, so the runtime
// never reads unlocked with its keys gone.
func TestLosingUnlockLocksASessionANewerUnlockPublished(t *testing.T) {
	r := New()
	var keysLoaded atomic.Bool
	var unlockedDuringCleanup atomic.Bool
	r.SetOnLock(func() {
		// The loser locks before its cleanup clears anything.
		unlockedDuringCleanup.Store(unlockedDuringCleanup.Load() || r.IsUnlocked())
		keysLoaded.Store(false)
	})

	release, done, first := raceUnlock(tryUnlock(r))
	r.Lock() // a lock lands while the first unlock is still deriving
	if _, err := r.TryUnlock(func() (int, error) { keysLoaded.Store(true); return 1, nil }, nil); err != nil {
		t.Fatalf("second unlock failed: %v", err)
	}
	close(release)
	<-done

	if !errors.Is(first.err, ErrLockedDuringUnlock) {
		t.Fatalf("first unlock = %v, want it to lose", first.err)
	}
	if r.IsUnlocked() || keysLoaded.Load() || unlockedDuringCleanup.Load() {
		t.Fatalf("unlocked=%v keys=%v unlocked during a cleanup=%v; want the runtime locked before its keys are cleared",
			r.IsUnlocked(), keysLoaded.Load(), unlockedDuringCleanup.Load())
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
	releaseSecond, secondDone, second := raceUnlock(func(unlockFn func() error) error {
		_, err := r.TryUnlock(func() (int, error) {
			err := unlockFn()
			keysLoaded.Store(true)
			return 1, err
		}, nil)
		return err
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

	if first.err == nil || !errors.Is(second.err, ErrLockedDuringUnlock) {
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
	if _, err := r.TryUnlock(func() (int, error) { keysLoaded.Store(true); return 1, nil }, nil); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
	close(release)
	<-done

	if !errors.Is(first.err, ErrLockedDuringUnlock) {
		t.Fatalf("recovery = %v, want it to lose", first.err)
	}
	if r.IsUnlocked() || r.IsRecovery() || keysLoaded.Load() {
		t.Fatalf("unlocked=%v recovery=%v keys=%v; want the runtime locked and its keys cleared",
			r.IsUnlocked(), r.IsRecovery(), keysLoaded.Load())
	}
}

// A maintenance that cannot republish clears the keys it reloaded: the
// runtime is already locked, so no later Lock would.
func TestRefusedMaintenanceClearsWhatItReloaded(t *testing.T) {
	r := New()
	var keysLoaded atomic.Bool
	r.SetOnLock(func() { keysLoaded.Store(false) })
	r.SetUnlocked()

	token := r.BeginMaintenance()
	keysLoaded.Store(true) // the maintenance reloads under the new passphrase
	r.Lock()               // a lock lands before it finishes
	if r.FinishMaintenance(token, true) {
		t.Fatal("maintenance republished over a lock")
	}
	if r.IsUnlocked() || keysLoaded.Load() {
		t.Fatalf("unlocked=%v keys=%v; want the runtime locked and the reload cleared", r.IsUnlocked(), keysLoaded.Load())
	}
}

// A maintenance that began on a runtime already locked never publishes
// unlocked state: a lock that landed after its caller checked the state
// stays in force.
func TestMaintenanceBegunLockedStaysLocked(t *testing.T) {
	r := New()
	r.SetUnlocked()
	r.Lock() // after the caller's check, before BeginMaintenance
	if r.FinishMaintenance(r.BeginMaintenance(), true) || r.IsUnlocked() {
		t.Fatal("a maintenance begun on a locked runtime published unlocked state")
	}
}
