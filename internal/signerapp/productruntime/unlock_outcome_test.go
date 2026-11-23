// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// countPassphraseChecks counts the unlock's passphrase checks against the
// store root, each one derivation, and runs them as they run.
func countPassphraseChecks(t *testing.T) *int {
	t.Helper()
	verify := verifyUnlockPassphrase
	t.Cleanup(func() { verifyUnlockPassphrase = verify })
	checks := new(int)
	verifyUnlockPassphrase = func(passphrase []byte, paths storepaths.Paths) error {
		*checks++
		return verify(passphrase, paths)
	}
	return checks
}

// A passphrase that does not open the store root ends an unlock request of
// a signer that is not unlocked where the request opens the root, before its
// reconcile: the opening is that request's passphrase check, the one
// derivation it makes. It neither reconciles, checks the passphrase again,
// nor loads, and enters no recovery. An unlock request once reconciled
// first, and went on from the failed reconcile to an entry into recovery,
// which opened the root again before it failed.
func TestAWrongPassphraseEndsAnUnlockAtTheStoreRootOpen(t *testing.T) {
	ir, _, loads, _ := unlockedRuntimeForTest(t)
	ir.Lock()
	checks := countPassphraseChecks(t)
	reconcile, reconciles := countReconciles()

	outcome, err := ir.Unlock([]byte("not the passphrase"), reconcile, nil)
	if !errors.Is(err, ErrInvalidPassphrase) || err.Error() != "invalid passphrase" {
		t.Fatalf("Unlock() = %+v, %v; want an invalid passphrase", outcome, err)
	}
	if *reconciles != 0 || *checks != 0 || loads.Load() != 0 {
		t.Fatalf("%d reconcile(s), %d passphrase check(s), %d load(s); want none", *reconciles, *checks, loads.Load())
	}
	if got := ir.GetState(); got != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v, want locked", got)
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("WithKeyring() = %v, want no keyring", err)
	}
}

// A good unlock of a locked signer reconciles with the keyring its opening
// of the store root gave it, and loads once: two derivations, the opening
// and the load's. It checks the passphrase no other way.
func TestAGoodUnlockReconcilesWithTheKeyringItOpened(t *testing.T) {
	ir, _, loads, _ := unlockedRuntimeForTest(t)
	ir.Lock()
	checks := countPassphraseChecks(t)
	var given *crypto.Keyring
	reconcile := func(kr *crypto.Keyring) error {
		given = kr
		return nil
	}
	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), reconcile, nil); err != nil || !ir.IsUnlocked() {
		t.Fatalf("Unlock() = %v, state %v; want unlocked", err, ir.GetState())
	}
	if given == nil || *checks != 0 || loads.Load() != 1 {
		t.Fatalf("reconciled with %v, %d passphrase check(s), %d load(s); want a keyring, none and one", given, *checks, loads.Load())
	}
}

// An unlock request's outcome is decided by error values, not by text: each
// row injects one failure into an unlock of a locked signer, or one begun in
// recovery, and reads the outcome the daemon answers from.
func TestTheUnlockOutcomeIsDecidedByErrorValues(t *testing.T) {
	// Wrapped with text of its own, so only errors.Is can classify it.
	validation := fmt.Errorf("the store would not load: %w", fmt.Errorf("%w: 1 malformed key file(s)", signertemplates.ErrGenerationValidation))
	collision := fmt.Errorf("failed to rescan keys directory: %w",
		&apkeys.AddressCollisionError{Collisions: map[string][]string{"ADDR": {"keys/ADDR.key", "keys/ADDR.cos"}}})
	transient := errors.New("failed to rescan keys directory: injected read failure")
	reconcileFailure := errors.New("reconcile: durable audit unavailable")
	lockDuringReconcile := errors.New("unused: the lock wins")

	type want struct {
		err      error // nil for an outcome
		recovery bool
		cause    error
		state    signerruntime.SignerState
	}
	for _, tc := range []struct {
		name      string
		recovery  bool                    // the request begins in recovery
		open      func(ir *Runtime)       // what happens while the request opens the store root
		reconcile func(ir *Runtime) error // what the request's reconcile does and returns
		load      func(ir *Runtime) error // what its load does and returns
		after     func(ir *Runtime)       // onUnlocked
		want      want
		// notified is how many lock notifications the request itself sends:
		// one when it lost at a fence and locked the runtime for its cleanup.
		notified int32
	}{
		{name: "unlocks", want: want{state: signerruntime.SignerStateUnlocked}},
		{name: "reconcile fails", reconcile: func(*Runtime) error { return reconcileFailure },
			want: want{recovery: true, cause: reconcileFailure, state: signerruntime.SignerStateRecovery}},
		{name: "load finds a validation failure", load: func(*Runtime) error { return validation },
			want: want{recovery: true, cause: signertemplates.ErrGenerationValidation, state: signerruntime.SignerStateRecovery}},
		{name: "load finds an address collision", load: func(*Runtime) error { return collision },
			want: want{recovery: true, cause: apkeys.ErrAddressCollision, state: signerruntime.SignerStateRecovery}},
		{name: "load fails otherwise", load: func(*Runtime) error { return transient },
			want: want{err: transient, state: signerruntime.SignerStateLocked}},
		{name: "lost to a lock during the store root open", open: func(ir *Runtime) { ir.Lock() },
			want: want{err: signerruntime.ErrLockedDuringUnlock, state: signerruntime.SignerStateLocked}},
		{name: "lost to a lock during the load", load: func(ir *Runtime) error { ir.Lock(); return nil },
			want: want{err: signerruntime.ErrLockedDuringUnlock, state: signerruntime.SignerStateLocked}, notified: 1},
		// The load finds a content defect after a lock landed in it: the
		// request enters no recovery.
		{name: "lost to a lock during a load that fails", load: func(ir *Runtime) error { ir.Lock(); return validation },
			want: want{err: signerruntime.ErrLockedDuringUnlock, state: signerruntime.SignerStateLocked}},
		{name: "lost to a lock during the reconcile", reconcile: func(ir *Runtime) error { ir.Lock(); return nil },
			want: want{err: signerruntime.ErrLockedDuringUnlock, state: signerruntime.SignerStateLocked}},
		// The reconcile fails after a lock landed in it: the request enters
		// no recovery, which once moved the locked signer into recovery.
		{name: "lost to a lock during a reconcile that fails", reconcile: func(ir *Runtime) error { ir.Lock(); return lockDuringReconcile },
			want: want{err: signerruntime.ErrLockedDuringUnlock, state: signerruntime.SignerStateLocked}},
		{name: "met a recovery", recovery: true, load: func(ir *Runtime) error { ir.SetRecovery(); return nil },
			want: want{recovery: true, cause: signerruntime.ErrRecoveryDuringUnlock, state: signerruntime.SignerStateRecovery}},
		{name: "the reload after the publish enters recovery", after: func(ir *Runtime) { ir.EnterRecovery(nil) },
			want: want{recovery: true, state: signerruntime.SignerStateRecovery}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir, _, _, locks := unlockedRuntimeForTest(t)
			if tc.recovery {
				ir.EnterRecovery(nil)
			} else {
				ir.Lock()
			}
			reconciles := 0
			if tc.open != nil {
				open := openStoreRoot
				t.Cleanup(func() { openStoreRoot = open })
				openStoreRoot = func(dir string, passphrase []byte) (*crypto.Keyring, crypto.StoreRootSelection, error) {
					kr, selection, err := open(dir, passphrase)
					tc.open(ir)
					return kr, selection, err
				}
			}
			notifiedBefore := locks.Load()
			ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
				if passphrase != nil && tc.load != nil {
					if err := tc.load(ir); err != nil {
						return nil, err
					}
				}
				return &signertemplates.ReloadReport{}, nil
			})

			var onUnlocked func()
			if tc.after != nil {
				onUnlocked = func() { tc.after(ir) }
			}
			reconcile := func(*crypto.Keyring) error {
				reconciles++
				if tc.reconcile == nil {
					return nil
				}
				return tc.reconcile(ir)
			}
			outcome, err := ir.Unlock([]byte(secondUnlockPassphrase), reconcile, onUnlocked)
			switch {
			case tc.want.err != nil:
				if !errors.Is(err, tc.want.err) {
					t.Fatalf("Unlock() = %+v, %v; want %v", outcome, err, tc.want.err)
				}
			case err != nil:
				t.Fatalf("Unlock() error = %v, want an outcome", err)
			case outcome.Recovery != tc.want.recovery:
				t.Fatalf("Unlock() = %+v, want recovery %v", outcome, tc.want.recovery)
			case tc.want.cause == nil && outcome.Cause != nil:
				t.Fatalf("Unlock() cause = %v, want none: the reload told the session itself", outcome.Cause)
			case tc.want.cause != nil && !errors.Is(outcome.Cause, tc.want.cause):
				t.Fatalf("Unlock() cause = %v, want %v", outcome.Cause, tc.want.cause)
			}
			if got := ir.GetState(); got != tc.want.state {
				t.Fatalf("state = %v, want %v", got, tc.want.state)
			}
			if got := locks.Load() - notifiedBefore; got != tc.notified {
				t.Fatalf("the request sent %d lock notification(s), want %d", got, tc.notified)
			}
			if tc.open != nil && reconciles != 0 {
				t.Fatalf("the request reconciled %d time(s) after it lost at the store root open, want none", reconciles)
			}
			// A request that lost to a lock leaves no keyring: it opened
			// none, or its cleanup closed the one it opened.
			if errors.Is(tc.want.err, signerruntime.ErrLockedDuringUnlock) {
				if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, keystore.ErrStoreLocked) {
					t.Fatalf("WithKeyring() = %v after a request lost to a lock, want no keyring", err)
				}
			}
		})
	}
}
