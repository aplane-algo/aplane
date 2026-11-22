// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
)

// Two unlock requests at once run one after the other, each wholly under the
// store mutation lock. The second, whose reconcile would fail, finds the
// signer the first unlocked and answers from that session: it reconciles
// nothing and does not end the session. Its reconcile once ran beside the
// first's publish, and its entry into recovery, after a check that found no
// session, ended the session the first had just published.
func TestASecondUnlockWaitsForTheFirstAndAnswersFromItsSession(t *testing.T) {
	ir, _, loads, _ := unlockedRuntimeForTest(t)
	ir.Lock()
	passphrase := []byte(secondUnlockPassphrase)
	reconciling, proceed := make(chan struct{}), make(chan struct{})
	first := func(*crypto.Keyring) error {
		close(reconciling)
		<-proceed
		return nil
	}
	secondReconciles := 0
	second := func(*crypto.Keyring) error {
		secondReconciles++
		return errors.New("reconcile: a generation the root never selected appeared")
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := ir.Unlock(passphrase, first, nil)
		firstDone <- err
	}()
	<-reconciling // the first holds the store mutation lock
	type result struct {
		outcome UnlockOutcome
		err     error
	}
	secondDone := make(chan result, 1)
	go func() {
		outcome, err := ir.Unlock(passphrase, second, nil)
		secondDone <- result{outcome, err}
	}()
	close(proceed)

	if err := <-firstDone; err != nil {
		t.Fatalf("the first Unlock() = %v, want a publish", err)
	}
	got := <-secondDone
	if got.err != nil || got.outcome.Recovery {
		t.Fatalf("the second Unlock() = %+v, %v; want the first's session's answer", got.outcome, got.err)
	}
	if secondReconciles != 0 || loads.Load() != 1 {
		t.Fatalf("the second reconciled %d time(s), and %d load(s) ran; want none and the first's one", secondReconciles, loads.Load())
	}
	if !ir.IsUnlocked() {
		t.Fatalf("state = %v: the second unlock ended the session the first published", ir.GetState())
	}
}
