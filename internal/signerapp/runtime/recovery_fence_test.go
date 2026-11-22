// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package runtime

import (
	"errors"
	"sync/atomic"
	"testing"
)

type unlockOutcome struct {
	ok  bool
	err error
}

// startBlockedUnlock starts a TryUnlock whose unlock function waits for
// release, and returns once the function is running.
func startBlockedUnlock(rt *Runtime) (release chan struct{}, done chan unlockOutcome) {
	entered := make(chan struct{})
	release = make(chan struct{})
	done = make(chan unlockOutcome, 1)
	go func() {
		_, err := tryUnlock(rt, func() (int, error) {
			close(entered)
			<-release
			return 1, nil
		}, nil)
		done <- unlockOutcome{err == nil, err}
	}()
	<-entered
	return release, done
}

// An unlock compares the session as well as the lock generation before it
// publishes. A store change that ends in doubt enters recovery while an
// unlock on another connection is still running its unlock function (two
// Argon2id derivations and a reload, outside the store mutation lock); the
// unlock once published unlocked over that recovery, so the signer signed
// though the change's answer said signing was blocked. It now publishes
// nothing and leaves the signer in recovery, with the keyring recovery
// administration needs.
func TestAnUnlockInFlightDoesNotPublishOverALaterRecovery(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(*Runtime)
		enter func(*Runtime)
	}{
		{
			name:  "begun unlocked, a second unlock",
			start: func(rt *Runtime) { rt.SetUnlocked() },
			enter: func(rt *Runtime) { rt.SetRecovery() },
		},
		{
			name: "begun in recovery, a restore or rollback entering it again",
			start: func(rt *Runtime) {
				rt.SetUnlocked()
				rt.SetRecovery()
			},
			enter: func(rt *Runtime) { rt.SetRecovery() },
		},
		{
			name:  "begun locked, beside an unlock whose reconcile failed",
			start: func(*Runtime) {},
			enter: func(rt *Runtime) {
				if err := tryRecovery(rt, func() error { return nil }); err != nil {
					t.Fatalf("TryRecovery: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := New()
			var lockCalls atomic.Int32
			rt.SetOnLock(func() { lockCalls.Add(1) })
			tc.start(rt)
			release, done := startBlockedUnlock(rt)
			tc.enter(rt)
			close(release)
			got := <-done
			if got.ok || !errors.Is(got.err, ErrRecoveryDuringUnlock) {
				t.Fatalf("TryUnlock = ok %v, %v; want %v", got.ok, got.err, ErrRecoveryDuringUnlock)
			}
			if !rt.IsRecovery() {
				t.Fatalf("state = %v, want recovery", rt.GetState())
			}
			if lockCalls.Load() != 0 {
				t.Fatalf("%d lock cleanup(s) ran; recovery needs the keyring", lockCalls.Load())
			}
		})
	}
}

// A first unlock of a locked signer is not fenced by SetRecovery, which does
// nothing on a locked signer: the unlock publishes as before. Store
// mutations refuse a signer that is not unlocked, so none commits under it.
func TestSetRecoveryDuringAFirstUnlockLetsItPublish(t *testing.T) {
	rt := New()
	release, done := startBlockedUnlock(rt)
	rt.SetRecovery()
	close(release)
	if got := <-done; !got.ok || !rt.IsUnlocked() {
		t.Fatalf("TryUnlock = ok %v, %v, state %v; want unlocked", got.ok, got.err, rt.GetState())
	}
}
