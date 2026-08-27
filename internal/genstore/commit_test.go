// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var testStoreRootPassphrase = []byte("atomic-root-mint-passphrase")

func mintFirst(t *testing.T, paths storepaths.Paths, files map[string]string) storepaths.GenPaths {
	t.Helper()
	gen, err := Mint(paths, MintRequest{
		GenerationID: testGenA, FirstGeneration: true,
		InitialPassphrase: testStoreRootPassphrase, Integrity: testKeyring(t),
		Operation: "test-init", OperationID: "op-init",
		CreatedAt: time.Unix(1_753_500_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := writeTestGenerationAuthority(staged); err != nil {
				return err
			}
			for relative, content := range files {
				if err := os.WriteFile(filepath.Join(staged.Dir(), filepath.FromSlash(relative)), []byte(content), 0o600); err != nil {
					return err
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Mint(first) error = %v", err)
	}
	return gen
}

func selectedForTest(t *testing.T, paths storepaths.Paths) storepaths.GenPaths {
	t.Helper()
	gen, err := ResolveStoreRootWithKeyring(paths, testKeyring(t))
	if err != nil {
		t.Fatalf("ResolveStoreRootWithKeyring: %v", err)
	}
	return gen
}

func TestMintFirstGenerationCommitsStoreRoot(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	resolved := selectedForTest(t, paths)
	if resolved.GenerationID() != gen.GenerationID() {
		t.Fatalf("selected = %s, want %s", resolved.GenerationID(), gen.GenerationID())
	}
	if err := ValidateCurrent(resolved); err != nil {
		t.Fatalf("ValidateCurrent: %v", err)
	}
	manifest, err := ReadManifest(resolved)
	if err != nil || manifest.Operation != "test-init" || !manifest.Complete || len(manifest.Inventory) != 4 {
		t.Fatalf("manifest = %+v (%v)", manifest, err)
	}
	if _, err := os.Lstat(filepath.Join(paths.ProductDir(), "CURRENT")); !os.IsNotExist(err) {
		t.Fatalf("mint created retired CURRENT: %v", err)
	}
}

func TestMintSecondGenerationSealsParentAndCopiesIndependently(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintFirst(t, paths, map[string]string{"keys/A.key": "original"})
	second, err := Mint(paths, MintRequest{
		GenerationID: testGenB, Parent: first.GenerationID(), Integrity: testKeyring(t),
		Operation: "test-activation", OperationID: "op-2", CreatedAt: time.Unix(1_753_500_100, 0),
		Apply: func(staged storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(staged.KeysDir(), "B.key"), []byte("new"), 0o600)
		},
	})
	if err != nil {
		t.Fatalf("Mint(second): %v", err)
	}
	if err := ValidateSealed(first, testKeyring(t)); err != nil {
		t.Fatalf("parent not sealed: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(second.KeysDir(), "A.key")); err != nil || string(data) != "original" {
		t.Fatalf("copied content = %q, %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(second.KeysDir(), "A.key"), []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(first.KeysDir(), "A.key")); err != nil || string(data) != "original" {
		t.Fatalf("parent content changed = %q, %v", data, err)
	}
	if selectedForTest(t, paths).GenerationID() != second.GenerationID() {
		t.Fatal("successor was not selected")
	}
}

func TestMintApplyFailureLeavesRootExact(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	before, err := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("apply failed")
	_, err = Mint(paths, MintRequest{
		GenerationID: testGenB, Parent: first.GenerationID(), Integrity: testKeyring(t),
		Operation: "test-activation", OperationID: "op-2", CreatedAt: time.Unix(1_753_500_100, 0),
		Apply: func(storepaths.GenPaths) error { return injected },
	})
	if !errors.Is(err, injected) {
		t.Fatalf("Mint error = %v", err)
	}
	after, err := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
	if err != nil || string(after) != string(before) {
		t.Fatalf("root changed after apply failure: %v", err)
	}
	if selectedForTest(t, paths).GenerationID() != first.GenerationID() {
		t.Fatal("failed mint changed selection")
	}
}

func TestMintCandidateValidationFailurePrecedesPublicationAndRootCommit(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintFirst(t, paths, nil)
	before, err := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("semantic candidate rejected")
	_, err = Mint(paths, MintRequest{
		GenerationID: testGenB, Parent: first.GenerationID(), Integrity: testKeyring(t),
		Operation: "test-validation", OperationID: "op-validation", CreatedAt: time.Unix(1_753_500_100, 0),
		ValidateCandidate: func(storepaths.GenPaths) error { return injected },
	})
	if !errors.Is(err, injected) {
		t.Fatalf("Mint() error = %v", err)
	}
	after, err := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("candidate rejection changed store root: %v", err)
	}
	if _, err := os.Lstat(paths.GenerationDir(testGenB)); !os.IsNotExist(err) {
		t.Fatalf("candidate rejection published successor: %v", err)
	}
}

func TestMintCrashBeforeRootReplacementLeavesParentSelected(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	injected := errors.New("crash before root replacement")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpFileSync && filepath.Base(path) == storepaths.StoreRootName {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	_, err := Mint(paths, MintRequest{
		GenerationID: testGenB, Parent: first.GenerationID(), Integrity: testKeyring(t),
		Operation: "test-activation", OperationID: "op-2", CreatedAt: time.Unix(1_753_500_100, 0),
	})
	if !errors.Is(err, injected) {
		t.Fatalf("Mint error = %v", err)
	}
	fsutil.TestHook = nil
	if selectedForTest(t, paths).GenerationID() != first.GenerationID() {
		t.Fatal("pre-rename failure changed selection")
	}
}
