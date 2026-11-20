// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// A store in a retired layout carries an older marker, and initialization
// refuses it at the marker before writing a root.
func TestInitialStoreRootRefusesARetiredLayout(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	for name, content := range map[string]string{
		".keystore":   `{"version":5,"layout":"generations/v1","created":"2026-01-01T00:00:00Z"}`,
		"CURRENT":     testGenA,
		"keyring.enc": "{}",
	} {
		if err := os.WriteFile(filepath.Join(paths.ProductDir(), name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := CommitInitialStoreRoot(paths, testKeyring(t), []byte("passphrase"), testGenA)
	if want := "unsupported keystore marker version 5"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("CommitInitialStoreRoot() error = %v, want one containing %q", err, want)
	}
	if _, err := os.Lstat(paths.StoreRootPath()); !os.IsNotExist(err) {
		t.Fatalf("store root written over a retired layout: %v", err)
	}
}

// A passphrase change whose successor keyring is too large for any reader to
// reopen is refused before the root changes, so the old passphrase still
// opens the store.
func TestReplacementRootRefusesAKeyringTooLargeToReopen(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	parent := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	kr := testKeyring(t)
	if err := WriteSeal(parent, 1_753_500_100, kr); err != nil {
		t.Fatal(err)
	}
	before, err := crypto.ReadStoreRootExact(paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	// About 11,700 terms is the most a wrapped keyring holds within the
	// readers' limit.
	const terms = 13_000
	keys := make(map[int64][]byte, terms)
	for term := int64(1); term <= terms; term++ {
		keys[term] = bytes.Repeat([]byte{byte(term)}, 32)
	}
	successor, err := crypto.NewKeyringFromTermKeys(terms, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Zero()

	_, err = Mint(paths, MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            testGenB, Parent: parent.GenerationID(), Integrity: kr,
		OutgoingSealAlreadyWritten: true,
		ReplacementKeyring:         successor, ReplacementPassphrase: []byte("next passphrase"),
		Operation: "test-changepass", OperationID: "op-changepass", CreatedAt: time.Unix(1_753_500_100, 0),
	})
	if want := "build replacement store root: store root keyring exceeds size limit"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Mint() error = %v, want one containing %q", err, want)
	}
	after, err := crypto.ReadStoreRootExact(paths.ProductDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("store root changed: %v", err)
	}
	gen, opened, err := ResolveStoreRoot(paths, testStoreRootPassphrase)
	if err != nil || gen.GenerationID() != parent.GenerationID() {
		t.Fatalf("ResolveStoreRoot(old passphrase) = %v, %v; want %s", gen.GenerationID(), err, parent.GenerationID())
	}
	opened.Zero()
}
