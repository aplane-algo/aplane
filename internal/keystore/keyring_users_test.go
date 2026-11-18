// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"errors"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
)

func storeWithKeyring(t *testing.T) *FileKeyStore {
	t.Helper()
	fs := &FileKeyStore{cache: map[string]keys.KeyScanInfo{}}
	if err := fs.setKeyringForTest(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	return fs
}

// within runs fn and fails the test if it has not returned after d: the
// regression these tests guard against is a hang, which must fail rather
// than stall the package.
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", what, d)
	}
}

// waitForLockToTakeTheKeyring waits until ClearKeys has taken the keyring
// off the store.
func waitForLockToTakeTheKeyring(t *testing.T, fs *FileKeyStore) {
	t.Helper()
	within(t, 2*time.Second, "taking the keyring off the store", func() {
		for fs.keyringIsLoaded() {
			time.Sleep(time.Millisecond)
		}
	})
}

func keyringWorks(kr *crypto.Keyring) bool {
	_, err := kr.Seal([]byte("probe"), crypto.AccountKeyContext("PROBE"))
	return err == nil
}

// A WithKeyring callback reads the store again (an admin service asks for
// the active paths), and a lock arrives meanwhile. The callback's read must
// not wait behind the lock's ClearKeys, which waits for the callback: that
// cycle once hung the whole signer.
func TestWithKeyringCallbackReadsTheStoreWhileALockWaits(t *testing.T) {
	fs := storeWithKeyring(t)
	inside, proceed, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	stillWorks := make(chan bool, 1)
	go func() {
		done <- fs.WithKeyring(func(kr *crypto.Keyring) error {
			close(inside)
			<-proceed
			_, _ = fs.ActivePaths()
			_, _ = fs.List(t.Context())
			_ = fs.GetKeyTypes()
			stillWorks <- keyringWorks(kr)
			return nil
		})
	}()
	<-inside
	cleared := make(chan struct{})
	go func() {
		fs.ClearKeys()
		close(cleared)
	}()
	// Let ClearKeys take the store before the callback reads it.
	waitForLockToTakeTheKeyring(t, fs)
	select {
	case <-cleared:
		t.Fatal("ClearKeys returned while a callback was still using the keyring")
	default:
	}
	close(proceed)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WithKeyring() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the callback's read of the store never returned: it is waiting behind ClearKeys")
	}
	if !<-stillWorks {
		t.Fatal("the keyring was zeroed while the callback was still using it")
	}
	select {
	case <-cleared:
	case <-time.After(2 * time.Second):
		t.Fatal("ClearKeys did not return after the callback did")
	}
}

// While a lock waits for a callback, the store reads as locked: a new
// WithKeyring is refused at once rather than queued behind the lock. A
// callback may call WithKeyring itself.
func TestWithKeyringDuringALockIsRefusedAndMayNest(t *testing.T) {
	fs := storeWithKeyring(t)
	nested := fs.WithKeyring(func(*crypto.Keyring) error {
		return fs.WithKeyring(func(kr *crypto.Keyring) error {
			if !keyringWorks(kr) {
				return errors.New("nested keyring unusable")
			}
			return nil
		})
	})
	if nested != nil {
		t.Fatalf("nested WithKeyring() = %v", nested)
	}

	inside, proceed := make(chan struct{}), make(chan struct{})
	finished := make(chan struct{})
	go func() {
		_ = fs.WithKeyring(func(*crypto.Keyring) error {
			close(inside)
			<-proceed
			return nil
		})
		close(finished)
	}()
	<-inside
	cleared := make(chan struct{})
	go func() {
		fs.ClearKeys()
		close(cleared)
	}()
	waitForLockToTakeTheKeyring(t, fs)
	if err := fs.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("WithKeyring() while a lock waits = %v, want ErrStoreLocked", err)
	}
	close(proceed)
	within(t, 2*time.Second, "the callback and the lock", func() {
		<-finished
		<-cleared
	})
}

// Installing the keyring already installed changes nothing and zeroes
// nothing.
func TestReinstallingTheSameKeyringKeepsItUsable(t *testing.T) {
	kr, err := crypto.NewKeyringFromKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	fs := &FileKeyStore{cache: map[string]keys.KeyScanInfo{}}
	fs.setKeyringDirectlyForTest(kr)
	fs.setKeyringDirectlyForTest(kr)
	if err := fs.WithKeyring(func(got *crypto.Keyring) error {
		if got != kr || !keyringWorks(got) {
			return errors.New("the keyring was replaced or zeroed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A keyring replaced by another (an unlock of a store already unlocked) is
// zeroed only after the callbacks using it return, and new callbacks get the
// new keyring at once.
func TestReplacedKeyringIsZeroedAfterItsCallbacks(t *testing.T) {
	fs := storeWithKeyring(t)
	inside, proceed, done := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	var old *crypto.Keyring
	go func() {
		_ = fs.WithKeyring(func(kr *crypto.Keyring) error {
			old = kr
			close(inside)
			<-proceed
			done <- keyringWorks(kr)
			return nil
		})
	}()
	<-inside
	replacement, err := crypto.NewKeyringFromKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	replaced := make(chan struct{})
	go func() {
		fs.setKeyringDirectlyForTest(replacement)
		close(replaced)
	}()
	deadline := time.Now().Add(2 * time.Second)
	var got *crypto.Keyring
	for time.Now().Before(deadline) {
		_ = fs.WithKeyring(func(kr *crypto.Keyring) error { got = kr; return nil })
		if got == replacement {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got != replacement {
		t.Fatal("new callbacks did not get the replacement keyring while an old one ran")
	}
	close(proceed)
	if !<-done {
		t.Fatal("the old keyring was zeroed while its callback was using it")
	}
	within(t, 2*time.Second, "replacing the keyring", func() { <-replaced })
	if keyringWorks(old) {
		t.Fatal("the replaced keyring was not zeroed after its callback returned")
	}
}
