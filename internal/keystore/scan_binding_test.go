// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore_test

import (
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func initializedStore(t *testing.T, passphrase []byte) storepaths.Paths {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{DataDir: paths.Root(), Paths: paths, Role: noderole.RoleCosigner}); err != nil {
		t.Fatal(err)
	}
	return paths
}

func mintSuccessor(t *testing.T, paths storepaths.Paths, passphrase []byte, parent string) string {
	t.Helper()
	_, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	next, err := genstore.NewGenerationID(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID: next, Parent: parent, Operation: "test", OperationID: "test-" + next,
		CreatedAt: time.Now(), Integrity: kr,
	}); err != nil {
		t.Fatal(err)
	}
	return next
}

// A reload that fails after a root commit must bind the newly selected
// generation, never keep the superseded one: recovery maintenance acts on the
// binding, and the old generation is sealed and immutable.
func TestScanFailureBindsTheAuthenticatedSelection(t *testing.T) {
	passphrase := []byte("scan-binding-passphrase")
	paths := initializedStore(t, passphrase)
	ks := keystore.NewAtomicFileKeyStoreForPaths(paths)
	if err := ks.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	before, err := ks.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	next := mintSuccessor(t, paths, passphrase, before.GenerationID())

	keysDir := paths.GenerationPaths(next).KeysDir()
	if err := os.Chmod(keysDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keysDir, 0o700) })

	if err := ks.Scan(passphrase); err == nil {
		t.Fatal("Scan() succeeded on an unreadable selected generation")
	}
	after, err := ks.ActivePaths()
	if err != nil {
		t.Fatalf("ActivePaths() after a failed scan error = %v, want the authenticated selection", err)
	}
	if after.GenerationID() != next {
		t.Fatalf("ActivePaths() = %s, want the root's selection %s (superseded %s)", after.GenerationID(), next, before.GenerationID())
	}
}

// A root that no longer authenticates with the session keyring leaves no
// authority to bind.
func TestScanClearsBindingWhenRootStopsAuthenticating(t *testing.T) {
	passphrase := []byte("scan-binding-passphrase")
	paths := initializedStore(t, passphrase)
	ks := keystore.NewAtomicFileKeyStoreForPaths(paths)
	if err := ks.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	foreign := initializedStore(t, passphrase)
	root, err := os.ReadFile(foreign.StoreRootPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StoreRootPath(), root, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ks.Scan(passphrase); err == nil {
		t.Fatal("Scan() succeeded with a root sealed under another keyring")
	}
	if active, err := ks.ActivePaths(); err == nil {
		t.Fatalf("ActivePaths() = %s after the root stopped authenticating, want no binding", active.GenerationID())
	}
}
