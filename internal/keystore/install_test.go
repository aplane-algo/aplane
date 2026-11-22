// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// contentsOf is a store's contents bound to generation, with one key whose
// file names the generation and n scan warnings.
func contentsOf(paths storepaths.Paths, generation string, n int) Contents {
	selection := paths.GenerationPaths(generation)
	return Contents{
		Selection: &selection,
		Keys:      map[string]keys.KeyScanInfo{"ADDR": {KeyFile: generation + ".key"}},
		Warnings:  make([]keys.KeyScanWarning, n),
	}
}

// Install sets the keyring, the binding, the key cache and the warnings
// together: a reader under the cache lock sees all of one installation,
// never a keyring or a binding from one and a cache from another.
func TestInstallSetsTheContentsTogether(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	fs := storeWithKeyring(t)
	const a, b = "gen-1753800000-aaaaaaaa", "gen-1753800001-bbbbbbbb"
	installs := map[string]Contents{a: contentsOf(paths, a, 1), b: contentsOf(paths, b, 2)}
	keyrings := map[string]*crypto.Keyring{}
	for _, generation := range []string{a, b} {
		kr, err := crypto.NewKeyring()
		if err != nil {
			t.Fatal(err)
		}
		keyrings[generation] = kr
	}
	// The detached keyrings are not zeroed: the test installs them again.
	fs.Install(keyrings[a], installs[a])

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			generation := a
			if i%2 == 1 {
				generation = b
			}
			fs.Install(keyrings[generation], installs[generation])
		}
	}()
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		kr, generation, files, warnings := fs.contentsForTest()
		want := installs[generation]
		if kr != keyrings[generation] || files["ADDR"] != generation+".key" || warnings != len(want.Warnings) {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("a reader saw generation %s with cache %v, %d warning(s) and another installation's keyring: parts of two installations", generation, files, warnings)
		}
	}
	stop.Store(true)
	wg.Wait()
}

// Install returns the keyring it replaced, and that keyring is zeroed only
// once the WithKeyring callbacks still using it have returned: a callback
// that took the old keyring before the installation keeps a working copy.
func TestInstallReturnsTheReplacedKeyringZeroedOnlyWhenUnused(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	fs := storeWithKeyring(t)
	replacement, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}

	inCallback, release := make(chan struct{}), make(chan struct{})
	var termBefore, termInUse int64
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		_ = fs.WithKeyring(func(old *crypto.Keyring) error {
			termBefore = old.CurrentTerm()
			close(inCallback)
			<-release
			termInUse = old.CurrentTerm() // Zero resets it
			return nil
		})
	}()
	<-inCallback

	detached := fs.Install(replacement, contentsOf(paths, "gen-1753800002-cccccccc", 0))
	zeroed := make(chan struct{})
	go func() {
		detached.ZeroWhenUnused()
		close(zeroed)
	}()
	select {
	case <-zeroed:
		t.Fatal("the replaced keyring was zeroed while a callback still used it")
	case <-time.After(50 * time.Millisecond):
	}
	if err := fs.WithKeyring(func(kr *crypto.Keyring) error {
		if kr != replacement {
			t.Error("WithKeyring does not hand out the installed keyring")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-callbackDone
	within(t, 5*time.Second, "zeroing the replaced keyring", func() { <-zeroed })
	if termBefore == 0 || termInUse != termBefore {
		t.Fatalf("the callback's keyring had term %d, then %d while still in use: zeroed under it", termBefore, termInUse)
	}
}
