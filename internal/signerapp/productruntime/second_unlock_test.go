// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
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
		KeyStore: keystore.NewAtomicFileKeyStoreForPaths(paths),
		KeyPaths: paths,
		OnLocked: func() { locks.Add(1) },
	})
	if err := ir.KeyStore().Unlock([]byte(secondUnlockPassphrase)); err != nil {
		t.Fatal(err)
	}
	loads = &atomic.Int32{}
	ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if passphrase != nil {
			loads.Add(1)
		}
		return &signertemplates.ReloadReport{}, nil
	})
	mutation = &hookedLock{}
	ir.SetReloadMutationLock(func() sync.Locker { return mutation })
	ir.SetUnlocked()
	return ir, mutation, loads, locks
}

// An unlock attempt that finds the signer unlocked answers from the session
// at its check and ends there, before the fence. A lock that comes after the
// check stands, and the attempt runs no cleanup of its own: it loaded
// nothing. Through the fence, an attempt that saw the lock generation move
// would lock again and clear, and could clear a session a passphrase change
// had republished in between.
func TestAnUnlockThatFindsTheSignerUnlockedEndsAtItsCheck(t *testing.T) {
	ir, mutation, loads, locks := unlockedRuntimeForTest(t)
	before := ir.LockGeneration()
	mutation.afterRelease = ir.Lock // after the check, where the fence would be

	unlockedCalls := 0
	ok, keyCount, msg := ir.TryUnlock([]byte(secondUnlockPassphrase), func() { unlockedCalls++ })
	if !ok || msg != "" || keyCount != 0 {
		t.Fatalf("TryUnlock() = (%v, %d, %q), want the session's answer", ok, keyCount, msg)
	}
	if got := loads.Load(); got != 0 {
		t.Fatalf("the attempt loaded %d time(s), want none", got)
	}
	if unlockedCalls != 0 {
		t.Fatal("the attempt ran the unlocked callback, which only a publish runs")
	}
	if ir.GetState() != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v, want the lock that came after the check to stand", ir.GetState())
	}
	if got := ir.LockGeneration(); got != before+1 {
		t.Fatalf("the session generation moved by %d, want 1 (the lock's): a loser's cleanup moves it again", got-before)
	}
	if got := locks.Load(); got != 1 {
		t.Fatalf("%d lock notifications, want the lock's one", got)
	}
}

// A wrong passphrase on an unlocked signer is refused, by TryUnlock and by
// AnswerIfUnlocked, and leaves the session as it was. The right one answers
// with the session's key count; on a signer that is not unlocked,
// AnswerIfUnlocked does not answer, and the unlock goes on.
func TestAnUnlockOfAnUnlockedSignerChecksThePassphrase(t *testing.T) {
	ir, _, loads, _ := unlockedRuntimeForTest(t)
	generation, _ := ir.UnlockedGeneration()
	wrong := []byte("not the passphrase")
	if ok, _, msg := ir.TryUnlock(wrong, nil); ok || msg != InvalidPassphraseMessage {
		t.Fatalf("TryUnlock(wrong) = (%v, %q), want %q", ok, msg, InvalidPassphraseMessage)
	}
	if answered, _, msg := ir.AnswerIfUnlocked(wrong); !answered || msg != InvalidPassphraseMessage {
		t.Fatalf("AnswerIfUnlocked(wrong) = (%v, %q), want %q", answered, msg, InvalidPassphraseMessage)
	}
	if answered, keyCount, msg := ir.AnswerIfUnlocked([]byte(secondUnlockPassphrase)); !answered || msg != "" || keyCount != ir.KeyCount() {
		t.Fatalf("AnswerIfUnlocked() = (%v, %d, %q), want the session's key count", answered, keyCount, msg)
	}
	if loads.Load() != 0 || !ir.IsUnlockedIn(generation) {
		t.Fatal("a refused or answered unlock loaded or ended the session")
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("the session's keyring is closed: %v", err)
	}
	ir.Lock()
	if answered, _, _ := ir.AnswerIfUnlocked(wrong); answered {
		t.Fatal("AnswerIfUnlocked() answered for a locked signer")
	}
}

// An unlock from recovery checks the state and loads under the store
// mutation lock, which a reconcile holds across its promotion out of
// recovery, so no promotion lands between the check and the end of the load.
// It publishes only after it has released the lock.
func TestAnUnlockLoadsUnderTheStoreMutationLock(t *testing.T) {
	ir, mutation, _, _ := unlockedRuntimeForTest(t)
	ir.SetRecovery()
	heldDuringLoad := false
	ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if passphrase != nil {
			heldDuringLoad = !mutation.TryLock()
			if !heldDuringLoad {
				mutation.Mutex.Unlock()
			}
		}
		return &signertemplates.ReloadReport{}, nil
	})
	stateAtRelease := signerruntime.SignerStateUnlocked
	mutation.afterRelease = func() { stateAtRelease = ir.GetState() }
	if ok, _, msg := ir.TryUnlock([]byte(secondUnlockPassphrase), nil); !ok {
		t.Fatalf("TryUnlock() from recovery = %q, want a publish", msg)
	}
	if !heldDuringLoad {
		t.Fatal("the load ran without the store mutation lock")
	}
	if stateAtRelease != signerruntime.SignerStateRecovery {
		t.Fatalf("state when the lock was released = %v, want recovery: the publish comes after", stateAtRelease)
	}
	if !ir.IsUnlocked() {
		t.Fatalf("state = %v, want unlocked", ir.GetState())
	}
}
