// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestStoreRootCommitInitialAndOrdinarySelection(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	passphrase := []byte("passphrase")
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	if err := CommitInitialStoreRoot(paths, kr, passphrase, testGenA); err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{filepath.Join(paths.ProductDir(), "CURRENT"), filepath.Join(paths.ProductDir(), "keyring.enc")} {
		if _, err := os.Lstat(retired); !os.IsNotExist(err) {
			t.Fatalf("retired layout artifact exists at %s: %v", retired, err)
		}
	}

	mintTestGeneration(t, paths, testGenB, map[string]string{"keys/B.key": "b"})
	if err := WriteSeal(first, 1_700_000_002, kr); err != nil {
		t.Fatal(err)
	}
	before, err := crypto.ReadStoreRootExact(paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitStoreRoot(paths, kr, testGenA, testGenB); err != nil {
		t.Fatal(err)
	}
	after, err := crypto.ReadStoreRootExact(paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("ordinary root commit did not replace the root")
	}
	gen, opened, err := ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Zero()
	if gen.GenerationID() != testGenB {
		t.Fatalf("resolved generation = %s, want %s", gen.GenerationID(), testGenB)
	}
}

func TestCommitStoreRootRequiresExactOutgoingSeal(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintTestGeneration(t, paths, testGenA, nil)
	mintTestGeneration(t, paths, testGenB, nil)
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	if err := CommitInitialStoreRoot(paths, kr, []byte("passphrase"), testGenA); err != nil {
		t.Fatal(err)
	}
	if err := CommitStoreRoot(paths, kr, testGenA, testGenB); err == nil {
		t.Fatal("CommitStoreRoot accepted an unsealed outgoing generation")
	}
	if err := WriteSeal(paths.GenerationPaths(testGenA), 1_700_000_002, kr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.GenerationDir(testGenA), "keys", "late.key"), []byte("tamper"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CommitStoreRoot(paths, kr, testGenA, testGenB); err == nil {
		t.Fatal("CommitStoreRoot accepted a stale outgoing seal")
	}
}

func TestCommitStoreRootClassifiesVisibleUnconfirmedRename(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintTestGeneration(t, paths, testGenA, nil)
	mintTestGeneration(t, paths, testGenB, nil)
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	passphrase := []byte("passphrase")
	if err := CommitInitialStoreRoot(paths, kr, passphrase, testGenA); err != nil {
		t.Fatal(err)
	}
	if err := WriteSeal(first, 1_700_000_002, kr); err != nil {
		t.Fatal(err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == paths.ProductDir() {
			return errors.New("injected root directory sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	err = CommitStoreRoot(paths, kr, testGenA, testGenB)
	fsutil.TestHook = nil
	if !errors.Is(err, ErrStoreRootCommitDurabilityUnknown) {
		t.Fatalf("CommitStoreRoot() error = %v", err)
	}
	gen, opened, openErr := ResolveStoreRoot(paths, passphrase)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer opened.Zero()
	if gen.GenerationID() != testGenB {
		t.Fatalf("visible root selected %s, want %s", gen.GenerationID(), testGenB)
	}
}

func TestCommitStoreRootPreRenameFailureLeavesOldRootExact(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintTestGeneration(t, paths, testGenA, nil)
	mintTestGeneration(t, paths, testGenB, nil)
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	if err := CommitInitialStoreRoot(paths, kr, []byte("passphrase"), testGenA); err != nil {
		t.Fatal(err)
	}
	if err := WriteSeal(first, 1_700_000_002, kr); err != nil {
		t.Fatal(err)
	}
	before, err := crypto.ReadStoreRootExact(paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == paths.StoreRootPath() {
			return errors.New("injected pre-rename failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	err = CommitStoreRoot(paths, kr, testGenA, testGenB)
	fsutil.TestHook = nil
	if err == nil || errors.Is(err, ErrStoreRootCommitDurabilityUnknown) ||
		errors.Is(err, ErrStoreRootCommitStateUnknown) {
		t.Fatalf("CommitStoreRoot() error = %v, want definite non-commit", err)
	}
	after, err := crypto.ReadStoreRootExact(paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("pre-rename failure changed the root")
	}
}

func TestCommitStoreRootPreservesWrappedKeyringFromFreshRead(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintTestGeneration(t, paths, testGenA, nil)
	mintTestGeneration(t, paths, testGenB, nil)
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	passphrase := []byte("passphrase")
	if err := CommitInitialStoreRoot(paths, kr, passphrase, testGenA); err != nil {
		t.Fatal(err)
	}
	if err := WriteSeal(first, 1_700_000_002, kr); err != nil {
		t.Fatal(err)
	}

	// Replace the root with a separately wrapped but equally authorized root
	// before the ordinary commit. CommitStoreRoot must reread under the lock;
	// preserving a cached wrapper would restore the older KEK envelope.
	refreshed, err := crypto.SealStoreRoot(kr, passphrase, testGenA)
	if err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFileDurable(paths.StoreRootPath(), refreshed); err != nil {
		t.Fatal(err)
	}
	if err := CommitStoreRoot(paths, kr, testGenA, testGenB); err != nil {
		t.Fatal(err)
	}
	committed, err := crypto.ReadStoreRootExact(paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testWrappedStoreRootKeyring(t, refreshed), testWrappedStoreRootKeyring(t, committed)) {
		t.Fatal("ordinary commit did not preserve the wrapped keyring from its fresh root read")
	}
}

func testWrappedStoreRootKeyring(t *testing.T, root []byte) []byte {
	t.Helper()
	var decoded struct {
		Keyring json.RawMessage `json:"keyring"`
	}
	if err := json.Unmarshal(root, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded.Keyring
}
