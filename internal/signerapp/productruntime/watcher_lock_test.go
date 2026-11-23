// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
)

// waitSignallingLock is a store mutation lock that reports each Lock call
// before it waits, so a test can act while the caller waits for it.
type waitSignallingLock struct {
	sync.Mutex
	waiting chan struct{}
}

func (l *waitSignallingLock) Lock() {
	l.waiting <- struct{}{}
	l.Mutex.Lock()
}

// The watcher checks the signer's state under the store mutation lock, as
// every other caller of Reload does. It once checked before it took the lock:
// a lock could land while it waited, and an unlock then load and release the
// lock, and the watcher's reload, finding a defect, would publish its empty
// key snapshot on the locked signer, where SetRecovery does nothing, for the
// unlock to publish over. A change the watcher sees there is marked dirty,
// for the next unlock that publishes to reconcile, as one seen while locked
// is.
func TestTheWatcherChecksTheStateUnderTheStoreMutationLock(t *testing.T) {
	ir, _, _, _ := unlockedRuntimeForTest(t)
	var reloads atomic.Int32
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*Loaded, error) {
		reloads.Add(1)
		return selectionBuild(ir.KeyPaths(), kr)
	}, ReloadEffects{})
	lock := &waitSignallingLock{waiting: make(chan struct{}, 1)}
	ir.SetReloadMutationLock(func() sync.Locker { return lock })
	var onChange func() error
	ir.EnsureKeyWatcher(func(_ []string, _ context.Context, reload func() error) error {
		onChange = reload
		return nil
	})
	t.Cleanup(ir.StopKeyWatcher)

	lock.Mutex.Lock() // a store change holds the lock
	done := make(chan error, 1)
	go func() { done <- onChange() }()
	<-lock.waiting // the watcher saw a change and waits for the lock
	ir.Lock()
	lock.Unlock()

	if err := <-done; err != nil {
		t.Fatalf("watcher callback = %v, want nil", err)
	}
	if n := reloads.Load(); n != 0 {
		t.Fatalf("the watcher reloaded %d time(s) on a signer a lock took while it waited, want none", n)
	}
	ir.watcherMu.Lock()
	dirty := ir.dirty
	ir.watcherMu.Unlock()
	if !dirty {
		t.Fatal("the change was not marked dirty for the next unlock")
	}
}
