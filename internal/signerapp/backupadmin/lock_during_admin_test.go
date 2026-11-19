// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// A lock that lands while an admin operation runs under the keyring (a
// restore, a backup) waits for it, and the operation's own reads of the
// store's active paths, which the daemon's admin services make through
// ActiveKeyPaths, still answer. Before, the operation's second read lock
// queued behind the lock's ClearKeys, which waited for the operation, and
// signing, lock and shutdown all hung.
func TestALockDuringAnAdminOperationUnderTheKeyringCompletes(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	if _, err := ir.ActiveKeyPaths(); err != nil {
		t.Fatalf("ActiveKeyPaths() before the lock = %v", err)
	}

	locked := make(chan struct{})
	operation := make(chan error, 1)
	go func() {
		operation <- ir.WithKeyring(func(*crypto.Keyring) error {
			go func() {
				ir.Lock()
				close(locked)
			}()
			// Wait until the lock has taken the keyring off the store, which
			// it does only once it reaches ClearKeys: from then a new
			// WithKeyring is refused as locked.
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); errors.Is(err, keystore.ErrStoreLocked) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			_, _ = ir.ActiveKeyPaths()
			return nil
		})
	}()

	select {
	case err := <-operation:
		if err != nil {
			t.Fatalf("WithKeyring() = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the operation's read of the active paths never returned: it is queued behind the lock")
	}
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("the lock never completed")
	}
	if _, err := ir.ActiveKeyPaths(); err == nil {
		t.Fatal("the store still has active paths after the lock")
	}
	// The operation's failure path enters recovery to block signing from a
	// cache behind the root. The lock already did: the signer stays locked,
	// not in a recovery with no keyring.
	ir.SetRecovery()
	if ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("after a lock overtook an admin operation the state is %v, want locked", ir.GetState())
	}
}
