// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"testing"

	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
)

// The two tests here run an unlock request's steps in the order the daemon's
// UnlockIdentity runs them, with another connection's transition landed
// between two of them. The daemon cannot land one there: no lock is held and
// nothing in between can be hooked.
//
// Each records a defect of that sequence as the code stands. They call the
// steps by hand, so they do not follow a change to the request path: the
// one-hold unlock order removes these steps (TryUnlock, TryRecoveryUnlock,
// AnswerIfUnlocked), these tests go with them, and tests of the properties
// named here, driven through UnlockIdentity, take their place.

// Race 2. An unlock request whose reconcile failed checks whether another
// request has unlocked the signer meanwhile, and enters recovery if none has.
// The check and the entry are separate steps. A publish between them is ended
// by the entry: the session another request had just opened is over, and the
// signer is in recovery though that session's reconcile and load succeeded.
func TestAFailedReconcilesRecoveryEndsASessionPublishedAfterItsCheck(t *testing.T) {
	ir, _, _, _ := unlockedRuntimeForTest(t)
	passphrase := []byte(secondUnlockPassphrase)
	ir.Lock()

	// The request's reconcile failed; it checks for a session in service.
	if answer := ir.AnswerFromSession(passphrase); answer.Answered {
		t.Fatalf("AnswerFromSession() = %+v on a locked signer, want no answer", answer)
	}
	// Another request publishes.
	if ok, _, msg := ir.TryUnlock(passphrase, nil); !ok {
		t.Fatalf("the other request's TryUnlock() = %q, want a publish", msg)
	}
	published, _ := ir.UnlockedGeneration()
	// The request enters recovery.
	if ok, msg := ir.TryRecoveryUnlock(passphrase); !ok {
		t.Fatalf("TryRecoveryUnlock() = %q, want the entry as the code stands", msg)
	}

	// The property to keep: an unlock request's entry into recovery does
	// not end a session published after the request found none.
	if ir.IsUnlockedIn(published) || ir.GetState() != signerruntime.SignerStateRecovery {
		t.Fatalf("state = %v, want recovery with the published session ended, as the code stands", ir.GetState())
	}
}

// Race 3. A lock that lands during the passphrase check of an unlock request
// that found the signer unlocked is undone by that request: the session did
// not hold through the check, so the request is not answered from it, and it
// goes on to reconcile, load and publish as a request that found the signer
// locked does. Its generations are read after the lock, so its fence passes.
// The operator's lock is followed at once by an unlocked signer.
func TestALockDuringARedundantUnlocksCheckIsUndoneByThatUnlock(t *testing.T) {
	ir, _, loads, _ := unlockedRuntimeForTest(t)
	passphrase := []byte(secondUnlockPassphrase)
	lockDuringPassphraseCheck(t, ir)

	// UnlockIdentity's steps: answer from the session or reconcile, then
	// TryUnlock.
	reconciled := false
	answer, err := ir.AnswerIfUnlocked(passphrase, func() error {
		reconciled = true
		return nil
	})
	if err != nil || answer.Answered || !reconciled {
		t.Fatalf("AnswerIfUnlocked() = %+v, %v, reconciled %v; want no answer and a reconcile: the session ended during the check", answer, err, reconciled)
	}
	if got := ir.GetState(); got != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v after the lock, want locked", got)
	}
	ok, _, msg := ir.TryUnlock(passphrase, nil)

	// The property to keep: a lock that lands during an unlock request
	// stands, though the request found the signer unlocked.
	if !ok || !ir.IsUnlocked() || loads.Load() != 1 {
		t.Fatalf("TryUnlock() = (%v, %q), state %v, %d load(s); want a load and a publish as the code stands", ok, msg, ir.GetState(), loads.Load())
	}
}
