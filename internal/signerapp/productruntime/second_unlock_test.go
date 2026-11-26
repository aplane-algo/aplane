// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keystore/keystoretest"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const secondUnlockPassphrase = "second-unlock-passphrase"

// hookedLock is a store mutation lock that runs afterRelease, once, after
// the first time it is released.
type hookedLock struct {
	sync.Mutex
	afterRelease func()
}

func (l *hookedLock) Unlock() {
	l.Mutex.Unlock()
	if hook := l.afterRelease; hook != nil {
		l.afterRelease = nil
		hook()
	}
}

// unlockedRuntimeForTest is a runtime over a fresh store with its keyring
// open and the signer unlocked, a session in service. loads counts the loads
// with a passphrase, and locks the lock notifications.
func unlockedRuntimeForTest(t *testing.T) (ir *Runtime, mutation *hookedLock, loads, locks *atomic.Int32) {
	t.Helper()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	if _, err := storeinit.Initialize([]byte(secondUnlockPassphrase), storeinit.Options{
		ValidateCandidate: func(storeinit.FirstGenerationCandidate) error { return nil },
		DataDir:           root,
		Paths:             paths,
	}); err != nil {
		t.Fatal(err)
	}
	locks = &atomic.Int32{}
	ir = New(Config{
		KeyStore: keystore.NewFileKeyStore(),
		KeyPaths: paths,
		OnLocked: func() { locks.Add(1) },
	})
	if err := keystoretest.Unlock(ir.KeyStore(), ir.KeyPaths(), []byte(secondUnlockPassphrase)); err != nil {
		t.Fatal(err)
	}
	loads = &atomic.Int32{}
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
		loads.Add(1)
		return selectionBuild(paths, kr)
	}, ReloadEffects{})
	mutation = &hookedLock{}
	ir.SetReloadMutationLock(func() sync.Locker { return mutation })
	ir.SetUnlocked()
	return ir, mutation, loads, locks
}

// selectionBuild is the reload's build reduced to the generation the store
// root selects, with no keys, no policy and no templates.
func selectionBuild(paths storepaths.Paths, kr *crypto.Keyring) (*Loaded, error) {
	selection, err := genstore.AuthenticateStoreRootSelection(paths, kr)
	if err != nil {
		return nil, err
	}
	return &Loaded{Selection: &selection, Contents: keystore.Contents{Selection: &selection}}, nil
}

// countReconciles is an unlock request's reconcile that counts its runs and
// succeeds.
func countReconciles() (reconcile func(*crypto.Keyring) error, runs *int) {
	runs = new(int)
	return func(*crypto.Keyring) error { *runs++; return nil }, runs
}

// An unlock request that finds the signer unlocked answers from the session
// and ends there. A lock that comes after it stands, and the request runs no
// cleanup of its own: it loaded nothing. Through the fence, a request that
// saw the lock generation move would lock again and clear, and could clear a
// session a passphrase change had republished in between.
func TestAnUnlockThatFindsTheSignerUnlockedEndsAtItsCheck(t *testing.T) {
	ir, mutation, loads, locks := unlockedRuntimeForTest(t)
	before := ir.LockGeneration()
	mutation.afterRelease = func() { ir.Lock() } // after the answer, as soon as the lock is free
	reconcile, reconciles := countReconciles()

	unlockedCalls := 0
	outcome, err := ir.Unlock([]byte(secondUnlockPassphrase), reconcile, func() { unlockedCalls++ })
	if err != nil || outcome.Recovery || outcome.KeyCount != 0 {
		t.Fatalf("Unlock() = %+v, %v; want the session's answer", outcome, err)
	}
	if got := loads.Load(); got != 0 || *reconciles != 0 {
		t.Fatalf("the request loaded %d time(s) and reconciled %d, want neither", got, *reconciles)
	}
	if unlockedCalls != 0 {
		t.Fatal("the request ran the unlocked callback, which only a publish runs")
	}
	if ir.GetState() != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v, want the lock that came after the answer to stand", ir.GetState())
	}
	if got := ir.LockGeneration(); got != before+1 {
		t.Fatalf("the session generation moved by %d, want 1 (the lock's): a loser's cleanup moves it again", got-before)
	}
	if got := locks.Load(); got != 1 {
		t.Fatalf("%d lock notifications, want the lock's one", got)
	}
}

// A wrong passphrase on an unlocked signer is refused and leaves the session
// as it was. The right one answers with the session's key count. Neither
// reconciles or loads. On a signer that is not unlocked a wrong passphrase
// ends the request where the store root does not open, before the reconcile.
func TestAnUnlockOfAnUnlockedSignerChecksThePassphrase(t *testing.T) {
	ir, _, loads, _ := unlockedRuntimeForTest(t)
	generation, _ := ir.UnlockedGeneration()
	reconcile, reconciles := countReconciles()
	wrong := []byte("not the passphrase")
	if _, err := ir.Unlock(wrong, reconcile, nil); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("Unlock(wrong) = %v, want %v", err, ErrInvalidPassphrase)
	}
	if outcome, err := ir.Unlock([]byte(secondUnlockPassphrase), reconcile, nil); err != nil || outcome.KeyCount != ir.KeyCount() {
		t.Fatalf("Unlock() = %+v, %v; want the session's key count", outcome, err)
	}
	if loads.Load() != 0 || *reconciles != 0 || !ir.IsUnlockedIn(generation) {
		t.Fatal("a refused or answered unlock loaded, reconciled or ended the session")
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("the session's keyring is closed: %v", err)
	}
	ir.Lock()
	if _, err := ir.Unlock(wrong, reconcile, nil); !errors.Is(err, ErrInvalidPassphrase) || *reconciles != 0 || loads.Load() != 0 {
		t.Fatalf("Unlock(wrong) on a locked signer = %v with %d reconcile(s) and %d load(s), want %v and neither", err, *reconciles, loads.Load(), ErrInvalidPassphrase)
	}
}

// lockDuringPassphraseCheck makes the next passphrase check lock the signer
// once it has checked, so the lock lands during the check.
func lockDuringPassphraseCheck(t *testing.T, ir *Runtime) {
	t.Helper()
	verify := verifyUnlockPassphrase
	t.Cleanup(func() { verifyUnlockPassphrase = verify })
	verifyUnlockPassphrase = func(passphrase []byte, paths storepaths.Paths) error {
		verifyUnlockPassphrase = verify
		err := verify(passphrase, paths)
		ir.Lock()
		return err
	}
}

// A lock that lands during the passphrase check of a request that found the
// signer unlocked wins: the request is answered that the signer locked, and
// does not unlock it again. It loads nothing. The request once went on to
// load and publish as one that found the signer locked does, and the
// operator's lock was followed at once by an unlocked signer.
func TestALockDuringThePassphraseCheckIsNotAnsweredFromTheSession(t *testing.T) {
	ir, _, loads, _ := unlockedRuntimeForTest(t)
	lockDuringPassphraseCheck(t, ir)
	reconcile, reconciles := countReconciles()
	if outcome, err := ir.Unlock([]byte(secondUnlockPassphrase), reconcile, nil); !errors.Is(err, signerruntime.ErrLockedDuringUnlock) {
		t.Fatalf("Unlock() = %+v, %v after a lock during the check, want %v", outcome, err, signerruntime.ErrLockedDuringUnlock)
	}
	if got := loads.Load(); got != 0 || *reconciles != 0 {
		t.Fatalf("the request loaded %d time(s) and reconciled %d, want neither", got, *reconciles)
	}
	if ir.GetState() != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v, want the lock to stand", ir.GetState())
	}
}

// An unlock from recovery holds the store mutation lock from its state read
// to its publish, so no store change, reconcile or passphrase change lands
// inside it. The watcher starts after the lock is released, since its reload
// of changes seen while locked takes the lock.
func TestAnUnlockLoadsUnderTheStoreMutationLock(t *testing.T) {
	ir, mutation, _, _ := unlockedRuntimeForTest(t)
	ir.EnterRecovery(nil)
	heldDuringLoad := false
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
		heldDuringLoad = !mutation.TryLock()
		if !heldDuringLoad {
			mutation.Mutex.Unlock()
		}
		return selectionBuild(ir.KeyPaths(), kr)
	}, ReloadEffects{})
	stateAtRelease := signerruntime.SignerStateRecovery
	mutation.afterRelease = func() { stateAtRelease = ir.GetState() }
	heldInCallback := true
	reconcile, _ := countReconciles()
	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), reconcile, func() {
		heldInCallback = !mutation.TryLock()
		if !heldInCallback {
			mutation.Mutex.Unlock()
		}
	}); err != nil {
		t.Fatalf("Unlock() from recovery = %v, want a publish", err)
	}
	if !heldDuringLoad {
		t.Fatal("the load ran without the store mutation lock")
	}
	if stateAtRelease != signerruntime.SignerStateUnlocked {
		t.Fatalf("state when the lock was released = %v, want unlocked: the publish comes before", stateAtRelease)
	}
	if heldInCallback {
		t.Fatal("the unlocked callback ran under the store mutation lock")
	}
}
