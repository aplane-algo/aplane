// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func mintFirst(t *testing.T, paths storepaths.Paths, files map[string]string) storepaths.GenPaths {
	t.Helper()
	gen, err := Mint(paths, MintRequest{
		GenerationID:    testGenA,
		FirstGeneration: true,
		Operation:       "test-init",
		OperationID:     "op-init",
		CreatedAt:       time.Unix(1_753_500_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := writeTestGenerationAuthority(staged); err != nil {
				return err
			}
			for relative, content := range files {
				if err := os.WriteFile(filepath.Join(staged.Dir(), filepath.FromSlash(relative)), []byte(content), 0o660); err != nil {
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

func TestMintFirstGenerationCommits(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})

	resolved, err := Resolve(paths)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolved.GenerationID() != gen.GenerationID() {
		t.Fatalf("CURRENT = %s, want %s", resolved.GenerationID(), gen.GenerationID())
	}
	if err := ValidateCurrent(resolved); err != nil {
		t.Fatalf("ValidateCurrent() error = %v", err)
	}
	manifest, err := ReadManifest(resolved)
	if err != nil {
		t.Fatalf("ReadManifest() error = %v", err)
	}
	if manifest.Operation != "test-init" || !manifest.Complete || len(manifest.Inventory) != 4 {
		t.Fatalf("manifest = %+v", manifest)
	}
	// No staging residue.
	entries, err := os.ReadDir(paths.GenerationsDir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("generations dir entries = %d (%v), want 1", len(entries), err)
	}
}

func TestMintSecondGenerationSealsParentAndCopiesIndependently(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintFirst(t, paths, map[string]string{"keys/A.key": "original"})

	second, err := Mint(paths, MintRequest{
		GenerationID: testGenB,
		Parent:       first.GenerationID(),
		Integrity:    testKeyring(t),
		Operation:    "test-activation",
		OperationID:  "op-2",
		CreatedAt:    time.Unix(1_753_500_100, 0),
		Apply: func(staged storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(staged.KeysDir(), "B.key"), []byte("new"), 0o660)
		},
	})
	if err != nil {
		t.Fatalf("Mint(second) error = %v", err)
	}

	// Parent is sealed and validates as a rollback target.
	if err := ValidateSealed(first, testKeyring(t)); err != nil {
		t.Fatalf("parent not sealed after flip: %v", err)
	}
	// The copy is content-complete...
	data, err := os.ReadFile(filepath.Join(second.KeysDir(), "A.key"))
	if err != nil || string(data) != "original" {
		t.Fatalf("copied content = %q, %v", data, err)
	}
	// ...and independent: writing the new generation must not reach the
	// parent's inode.
	if err := os.WriteFile(filepath.Join(second.KeysDir(), "A.key"), []byte("mutated"), 0o660); err != nil {
		t.Fatalf("mutate copy: %v", err)
	}
	parentData, err := os.ReadFile(filepath.Join(first.KeysDir(), "A.key"))
	if err != nil || string(parentData) != "original" {
		t.Fatalf("parent content after child mutation = %q, %v (shared inode?)", parentData, err)
	}
	if err := ValidateSealed(first, testKeyring(t)); err != nil {
		t.Fatalf("parent seal broken by child mutation: %v", err)
	}
}

func TestMintApplyFailureLeavesOldGenerationAuthoritative(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})

	injected := errors.New("apply failed")
	_, err := Mint(paths, MintRequest{
		GenerationID: testGenB,
		Parent:       first.GenerationID(),
		Integrity:    testKeyring(t),
		Operation:    "test-activation",
		OperationID:  "op-2",
		CreatedAt:    time.Unix(1_753_500_100, 0),
		Apply:        func(storepaths.GenPaths) error { return injected },
	})
	if !errors.Is(err, injected) {
		t.Fatalf("Mint error = %v, want injected apply failure", err)
	}
	resolved, resolveErr := Resolve(paths)
	if resolveErr != nil || resolved.GenerationID() != first.GenerationID() {
		t.Fatalf("CURRENT after failed mint = %s (%v), want untouched %s", resolved.GenerationID(), resolveErr, first.GenerationID())
	}
	entries, err := os.ReadDir(paths.GenerationsDir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("staging residue after failed mint: %d entries (%v)", len(entries), err)
	}
}

// TestMintCrashMatrix simulates a crash (via injected fsutil failures) at
// every durability boundary of the commit and asserts the store afterwards
// resolves to exactly the complete old state or the complete new state.
func TestMintCrashMatrix(t *testing.T) {
	type step struct {
		op   fsutil.HookOp
		path string // substring match; empty = any
	}
	crashPoints := []struct {
		name string
		step step
	}{
		{"before-seal-write", step{fsutil.OpFileSync, storepaths.GenerationSealName}},
		{"before-seal-rename", step{fsutil.OpRename, storepaths.GenerationSealName}},
		{"before-pointer-write", step{fsutil.OpFileSync, storepaths.CurrentPointerName}},
		{"before-pointer-rename", step{fsutil.OpRename, storepaths.CurrentPointerName}},
	}
	for _, crash := range crashPoints {
		t.Run(crash.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			first := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})

			injected := errors.New("simulated crash: " + crash.name)
			fsutil.TestHook = func(op fsutil.HookOp, path string) error {
				if op == crash.step.op && (crash.step.path == "" || filepath.Base(path) == crash.step.path) {
					return injected
				}
				return nil
			}
			_, err := Mint(paths, MintRequest{
				GenerationID: testGenB,
				Parent:       first.GenerationID(),
				Integrity:    testKeyring(t),
				Operation:    "test-activation",
				OperationID:  "op-2",
				CreatedAt:    time.Unix(1_753_500_100, 0),
				Apply: func(staged storepaths.GenPaths) error {
					return os.WriteFile(filepath.Join(staged.KeysDir(), "B.key"), []byte("b"), 0o660)
				},
			})
			fsutil.TestHook = nil
			if !errors.Is(err, injected) {
				t.Fatalf("Mint error = %v, want injected crash", err)
			}

			// The old generation must still be selected and valid.
			resolved, resolveErr := Resolve(paths)
			if resolveErr != nil {
				t.Fatalf("Resolve after crash: %v", resolveErr)
			}
			if resolved.GenerationID() != first.GenerationID() {
				t.Fatalf("CURRENT after crash = %s, want %s", resolved.GenerationID(), first.GenerationID())
			}
			if err := ValidateCurrent(resolved); err != nil {
				t.Fatalf("old generation invalid after crash: %v", err)
			}
			// The published-but-uncommitted attempt, if any, is identifiable
			// structurally: non-current and unsealed. (Reconciliation
			// discards it; it is never resumed.)
			attempt := paths.GenerationPaths(testGenB)
			if _, statErr := os.Lstat(attempt.Dir()); statErr == nil {
				sealed, sealErr := HasSeal(attempt)
				if sealErr != nil || sealed {
					t.Fatalf("uncommitted attempt sealed = (%v, %v), want unsealed", sealed, sealErr)
				}
			}
		})
	}
}

func TestRollbackToRequiresSealAndSealsOutgoing(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	_, err := Mint(paths, MintRequest{
		GenerationID: testGenB,
		Parent:       first.GenerationID(),
		Integrity:    testKeyring(t),
		Operation:    "test-activation",
		OperationID:  "op-2",
		CreatedAt:    time.Unix(1_753_500_100, 0),
	})
	if err != nil {
		t.Fatalf("Mint(second) error = %v", err)
	}

	if err := RollbackTo(paths, first.GenerationID(), time.Unix(1_753_500_200, 0), testKeyring(t)); err != nil {
		t.Fatalf("RollbackTo() error = %v", err)
	}
	resolved, err := Resolve(paths)
	if err != nil || resolved.GenerationID() != first.GenerationID() {
		t.Fatalf("CURRENT after rollback = %s (%v), want %s", resolved.GenerationID(), err, first.GenerationID())
	}
	// The rolled-away generation was sealed on the way out, so rolling
	// forward validates too.
	second := paths.GenerationPaths(testGenB)
	if err := ValidateSealed(second, testKeyring(t)); err != nil {
		t.Fatalf("outgoing generation not sealed by rollback: %v", err)
	}

	// A rollback target without a seal is refused.
	if err := os.Remove(second.SealPath()); err != nil {
		t.Fatalf("remove seal: %v", err)
	}
	if err := RollbackTo(paths, testGenB, time.Unix(1_753_500_300, 0), testKeyring(t)); err == nil {
		t.Fatal("RollbackTo accepted an unsealed target")
	}
}

// TestMintPointerFlipDirSyncFailureIsCommittedButUnverified covers the
// window where the CURRENT rename landed but the identity-directory sync
// failed: the commit is visible and must be reported as
// ErrCommitDurabilityUnknown, never as "nothing committed".
func TestMintPointerFlipDirSyncFailureIsCommittedButUnverified(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	first := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})

	identityDirBase := filepath.Base(paths.ProductDir())
	injected := errors.New("simulated crash: post-rename dir sync")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && filepath.Base(path) == identityDirBase {
			return injected
		}
		return nil
	}
	_, err := Mint(paths, MintRequest{
		GenerationID: testGenB,
		Parent:       first.GenerationID(),
		Integrity:    testKeyring(t),
		Operation:    "test-activation",
		OperationID:  "op-2",
		CreatedAt:    time.Unix(1_753_500_100, 0),
	})
	fsutil.TestHook = nil
	if !errors.Is(err, ErrCommitDurabilityUnknown) {
		t.Fatalf("Mint error = %v, want ErrCommitDurabilityUnknown", err)
	}

	// The flip is visible: CURRENT names the new generation and it
	// validates; the parent is sealed.
	resolved, resolveErr := Resolve(paths)
	if resolveErr != nil || resolved.GenerationID() != testGenB {
		t.Fatalf("CURRENT after unverified commit = %s (%v), want %s", resolved.GenerationID(), resolveErr, testGenB)
	}
	if err := ValidateCurrent(resolved); err != nil {
		t.Fatalf("committed generation invalid: %v", err)
	}
	if err := ValidateSealed(first, testKeyring(t)); err != nil {
		t.Fatalf("parent not sealed: %v", err)
	}
}

// TestWriteCurrentRetriesDirSyncOnce proves a transient post-rename sync
// failure self-heals without surfacing an error.
func TestWriteCurrentRetriesDirSyncOnce(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	gen := mintTestGeneration(t, paths, testGenC, nil)
	_ = gen

	identityDirBase := filepath.Base(paths.ProductDir())
	failures := 0
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && filepath.Base(path) == identityDirBase && failures == 0 {
			failures++
			return errors.New("transient sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	if err := WriteCurrent(paths, testGenC); err != nil {
		t.Fatalf("WriteCurrent() error = %v, want retried success", err)
	}
	current, err := ReadCurrent(paths)
	if err != nil || current != testGenC {
		t.Fatalf("CURRENT = %s (%v), want %s", current, err, testGenC)
	}
}
