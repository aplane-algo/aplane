// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	testGenC = "gen-1753500002-2badc0de"
	testGenD = "gen-1753500003-3badc0de"
)

// buildGenerationChain mints A (first), then B, then C, leaving CURRENT=C
// with A and B sealed priors.
func buildGenerationChain(t *testing.T, paths storepaths.Paths) {
	t.Helper()
	mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	for i, id := range []string{testGenB, testGenC} {
		parent := testGenA
		if i == 1 {
			parent = testGenB
		}
		if _, err := Mint(paths, testIdentity, MintRequest{
			GenerationID: id,
			Parent:       parent,
			Operation:    "test-activation",
			OperationID:  "op-" + id,
			CreatedAt:    time.Unix(1_753_500_100+int64(i), 0),
		}); err != nil {
			t.Fatalf("Mint(%s) error = %v", id, err)
		}
	}
}

func TestReconcileDiscardsAttemptsAndStagingKeepsSealedPriors(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)

	// A published-but-uncommitted attempt (no seal, not current) and a
	// leftover staging directory.
	attempt := paths.GenerationPaths(testIdentity, testGenD)
	for _, namespace := range []string{"keys", "keytypes"} {
		if err := os.MkdirAll(filepath.Join(attempt.Dir(), namespace), 0o770); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	if err := WriteManifest(attempt, Manifest{
		GenerationID: testGenD, CreatedAtUnix: 1, Operation: "test", OperationID: "op-d", Complete: true,
	}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	staging := filepath.Join(paths.GenerationsDir(testIdentity), storepaths.GenerationStagingPrefix+"leftover")
	if err := os.MkdirAll(staging, 0o770); err != nil {
		t.Fatalf("MkdirAll(staging): %v", err)
	}

	report, err := Reconcile(paths, testIdentity, nil)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if report.Current != testGenC {
		t.Fatalf("current = %s, want %s", report.Current, testGenC)
	}
	if !slices.Equal(report.DiscardedAttempts, []string{testGenD}) {
		t.Fatalf("discarded attempts = %v, want [%s]", report.DiscardedAttempts, testGenD)
	}
	if len(report.DiscardedStaging) != 1 {
		t.Fatalf("discarded staging = %v", report.DiscardedStaging)
	}
	if !slices.Equal(report.SealedPriors, []string{testGenB, testGenA}) {
		t.Fatalf("sealed priors = %v, want newest-first [%s %s]", report.SealedPriors, testGenB, testGenA)
	}
	if _, err := os.Lstat(attempt.Dir()); !os.IsNotExist(err) {
		t.Fatalf("uncommitted attempt survived reconciliation: %v", err)
	}
	// Sealed priors and current survive.
	for _, id := range []string{testGenA, testGenB, testGenC} {
		if _, err := os.Lstat(paths.GenerationPaths(testIdentity, id).Dir()); err != nil {
			t.Fatalf("generation %s missing after reconcile: %v", id, err)
		}
	}
}

func TestReconcileKeepsReferencedUnsealedAttempt(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	attempt := paths.GenerationPaths(testIdentity, testGenD)
	if err := os.MkdirAll(filepath.Join(attempt.Dir(), "keys"), 0o770); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	report, err := Reconcile(paths, testIdentity, map[string]bool{testGenD: true})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(report.DiscardedAttempts) != 0 {
		t.Fatalf("referenced attempt was discarded: %v", report.DiscardedAttempts)
	}
	if _, err := os.Lstat(attempt.Dir()); err != nil {
		t.Fatalf("referenced attempt missing: %v", err)
	}
}

func TestReconcileFailsClosedOnInvalidCurrent(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	if err := os.WriteFile(paths.CurrentPointerPath(testIdentity), []byte("garbage\n"), 0o660); err != nil {
		t.Fatalf("corrupt CURRENT: %v", err)
	}
	// Plant an attempt that must NOT be deleted while CURRENT is invalid.
	attempt := paths.GenerationPaths(testIdentity, testGenD)
	if err := os.MkdirAll(filepath.Join(attempt.Dir(), "keys"), 0o770); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	if _, err := Reconcile(paths, testIdentity, nil); err == nil {
		t.Fatal("Reconcile accepted an invalid CURRENT")
	}
	if _, err := os.Lstat(attempt.Dir()); err != nil {
		t.Fatalf("reconcile deleted state under an invalid CURRENT: %v", err)
	}
}

func TestReconcileFailsClosedOnUnexpectedEntry(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	if err := os.MkdirAll(filepath.Join(paths.GenerationsDir(testIdentity), "not-a-generation"), 0o770); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := Reconcile(paths, testIdentity, nil); err == nil {
		t.Fatal("Reconcile accepted an unexpected generations entry")
	}
}

func TestCollectGarbageRetainsCurrentPlusNewestSealedPrior(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths) // A, B sealed priors; C current

	removed, err := CollectGarbage(paths, testIdentity, nil, true)
	if err != nil {
		t.Fatalf("CollectGarbage() error = %v", err)
	}
	if !slices.Equal(removed, []string{testGenA}) {
		t.Fatalf("removed = %v, want oldest prior [%s]", removed, testGenA)
	}
	for _, id := range []string{testGenB, testGenC} {
		if _, err := os.Lstat(paths.GenerationPaths(testIdentity, id).Dir()); err != nil {
			t.Fatalf("retained generation %s missing: %v", id, err)
		}
	}
	// Rollback to the retained prior still works.
	if err := RollbackTo(paths, testIdentity, testGenB, time.Unix(1_753_500_400, 0)); err != nil {
		t.Fatalf("RollbackTo(retained prior) error = %v", err)
	}
}

func TestCollectGarbageHonorsReferences(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	removed, err := CollectGarbage(paths, testIdentity, map[string]bool{testGenA: true}, true)
	if err != nil {
		t.Fatalf("CollectGarbage() error = %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed referenced generation: %v", removed)
	}
}

func TestCollectGarbageAllPriorsReachesRotationQuiescence(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths) // A, B sealed priors; C current

	removed, err := CollectGarbage(paths, testIdentity, nil, false)
	if err != nil {
		t.Fatalf("CollectGarbage(all priors) error = %v", err)
	}
	if !slices.Equal(removed, []string{testGenB, testGenA}) {
		t.Fatalf("removed = %v, want both priors newest-first", removed)
	}
	entries, err := os.ReadDir(paths.GenerationsDir(testIdentity))
	if err != nil || len(entries) != 1 {
		t.Fatalf("generations after full prune = %d (%v), want only current", len(entries), err)
	}
}

// TestCollectGarbageRetainsManifestParentAfterRollback drives the retention
// trap: after a rollback the lexicographically newest prior is the
// rolled-away child, while the true rollback target is the current
// generation's manifest parent.
func TestCollectGarbageRetainsManifestParentAfterRollback(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths) // A -> B -> C, CURRENT=C
	if err := RollbackTo(paths, testIdentity, testGenB, time.Unix(1_753_500_500, 0)); err != nil {
		t.Fatalf("RollbackTo(B) error = %v", err)
	}
	// CURRENT=B; sealed priors are A (B's parent) and C (the rolled-away
	// child, lexicographically newest).

	removed, err := CollectGarbage(paths, testIdentity, nil, true)
	if err != nil {
		t.Fatalf("CollectGarbage() error = %v", err)
	}
	if !slices.Equal(removed, []string{testGenC}) {
		t.Fatalf("removed = %v, want the rolled-away child [%s]", removed, testGenC)
	}
	// The manifest parent survives and remains a valid rollback target.
	if err := ValidateSealed(paths.GenerationPaths(testIdentity, testGenA)); err != nil {
		t.Fatalf("manifest parent A invalid after prune: %v", err)
	}
	if err := RollbackTo(paths, testIdentity, testGenA, time.Unix(1_753_500_600, 0)); err != nil {
		t.Fatalf("RollbackTo(parent) error = %v", err)
	}
}

func TestCollectGarbageRefusesToPruneWhenRollbackParentInvalid(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths) // A -> B -> C, CURRENT=C
	if err := RollbackTo(paths, testIdentity, testGenB, time.Unix(1_753_500_500, 0)); err != nil {
		t.Fatalf("RollbackTo(B) error = %v", err)
	}
	// CURRENT=B, rollback parent A. Corrupt A's seal: A can no longer serve
	// as the rollback target, so the prune must delete nothing rather than
	// destroy C, the only other recovery material.
	sealPath := paths.GenerationPaths(testIdentity, testGenA).SealPath()
	if err := os.WriteFile(sealPath, []byte("{corrupt"), 0600); err != nil {
		t.Fatalf("corrupt seal: %v", err)
	}

	removed, err := CollectGarbage(paths, testIdentity, nil, true)
	if err == nil {
		t.Fatalf("CollectGarbage() = %v, want error for invalid rollback parent", removed)
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %v, want nothing deleted on aborted prune", removed)
	}
	for _, gen := range []string{testGenA, testGenC} {
		if _, statErr := os.Stat(paths.GenerationPaths(testIdentity, gen).Dir()); statErr != nil {
			t.Fatalf("generation %s missing after aborted prune: %v", gen, statErr)
		}
	}
}

func TestCollectGarbageRefusesToPruneWhenCurrentInvalid(t *testing.T) {
	for _, retainParent := range []bool{true, false} {
		t.Run(fmt.Sprintf("retainRollbackParent=%v", retainParent), func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			buildGenerationChain(t, paths) // A -> B -> C, CURRENT=C
			// The pointer resolves and the directory exists, but the current
			// generation is structurally broken: no manifest. Deleting any
			// prior now would abandon the only recovery material.
			manifest := paths.GenerationPaths(testIdentity, testGenC).ManifestPath()
			if err := os.Remove(manifest); err != nil {
				t.Fatalf("remove manifest: %v", err)
			}

			removed, err := CollectGarbage(paths, testIdentity, nil, retainParent)
			if err == nil {
				t.Fatalf("CollectGarbage() = %v, want error for invalid current generation", removed)
			}
			if len(removed) != 0 {
				t.Fatalf("removed = %v, want nothing deleted on aborted prune", removed)
			}
			for _, gen := range []string{testGenA, testGenB, testGenC} {
				if _, statErr := os.Stat(paths.GenerationPaths(testIdentity, gen).Dir()); statErr != nil {
					t.Fatalf("generation %s missing after aborted prune: %v", gen, statErr)
				}
			}
		})
	}
}

func TestCollectGarbageIsIdempotentAfterAllPriorsPrune(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths) // A -> B -> C, CURRENT=C
	if _, err := CollectGarbage(paths, testIdentity, nil, false); err != nil {
		t.Fatalf("CollectGarbage(all priors) error = %v", err)
	}
	// Current's immutable manifest still names the deleted parent B; an
	// ordinary prune must be a successful no-op, not a missing-parent error.
	removed, err := CollectGarbage(paths, testIdentity, nil, true)
	if err != nil {
		t.Fatalf("CollectGarbage(after all-priors) error = %v, want no-op", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %v, want nothing", removed)
	}
	if _, err := CollectGarbage(paths, testIdentity, nil, false); err != nil {
		t.Fatalf("CollectGarbage(all priors, repeated) error = %v, want no-op", err)
	}
}

func TestValidateCurrentRequiresBothNamespaces(t *testing.T) {
	for _, namespace := range []string{"keys", "keytypes"} {
		t.Run(namespace, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			buildGenerationChain(t, paths)
			gen := paths.GenerationPaths(testIdentity, testGenC)
			if err := ValidateCurrent(gen); err != nil {
				t.Fatalf("ValidateCurrent(intact) error = %v", err)
			}
			if err := os.RemoveAll(filepath.Join(gen.Dir(), namespace)); err != nil {
				t.Fatalf("remove namespace: %v", err)
			}
			if err := ValidateCurrent(gen); err == nil {
				t.Fatalf("ValidateCurrent accepted a generation missing %s/", namespace)
			}
			// The prune path inherits the rejection: nothing is deleted.
			removed, err := CollectGarbage(paths, testIdentity, nil, false)
			if err == nil {
				t.Fatalf("CollectGarbage() = %v, want error for missing namespace", removed)
			}
			for _, id := range []string{testGenA, testGenB} {
				if _, statErr := os.Stat(paths.GenerationPaths(testIdentity, id).Dir()); statErr != nil {
					t.Fatalf("prior %s deleted despite invalid current: %v", id, statErr)
				}
			}
		})
	}
}

func TestReconcileRetainsUnsealedRollbackParent(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths) // A -> B -> C, CURRENT=C
	// C's manifest names B as parent. B was committed once; deleting its
	// seal simulates damage — reconciliation must retain it as lineage,
	// never classify it as an uncommitted attempt.
	if err := os.Remove(paths.GenerationPaths(testIdentity, testGenB).SealPath()); err != nil {
		t.Fatalf("remove parent seal: %v", err)
	}

	report, err := Reconcile(paths, testIdentity, nil)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(report.DiscardedAttempts) != 0 {
		t.Fatalf("discarded = %v, want the unsealed parent retained", report.DiscardedAttempts)
	}
	if report.RetainedUnsealedParent != testGenB {
		t.Fatalf("RetainedUnsealedParent = %q, want %s", report.RetainedUnsealedParent, testGenB)
	}
	if _, err := os.Stat(paths.GenerationPaths(testIdentity, testGenB).Dir()); err != nil {
		t.Fatalf("unsealed parent deleted by reconciliation: %v", err)
	}

	// Both prune modes refuse while the damaged parent exists.
	for _, retainParent := range []bool{true, false} {
		removed, err := CollectGarbage(paths, testIdentity, nil, retainParent)
		if err == nil || len(removed) != 0 {
			t.Fatalf("CollectGarbage(retain=%v) = (%v, %v), want fail-closed refusal", retainParent, removed, err)
		}
	}
	if _, err := os.Stat(paths.GenerationPaths(testIdentity, testGenA).Dir()); err != nil {
		t.Fatalf("sealed prior A deleted despite refusal: %v", err)
	}
}

func TestReconcileDeletesNothingWhenCurrentManifestIncomplete(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	// Residue that reconciliation would normally delete.
	staging := filepath.Join(paths.GenerationsDir(testIdentity), storepaths.GenerationStagingPrefix+"leftover")
	if err := os.MkdirAll(staging, 0o770); err != nil {
		t.Fatalf("MkdirAll(staging): %v", err)
	}
	attempt := paths.GenerationPaths(testIdentity, testGenD)
	for _, namespace := range []string{"keys", "keytypes"} {
		if err := os.MkdirAll(filepath.Join(attempt.Dir(), namespace), 0o770); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	// Break the current generation's manifest.
	gen := paths.GenerationPaths(testIdentity, testGenC)
	if err := os.WriteFile(gen.ManifestPath(), []byte("{not json"), 0o660); err != nil {
		t.Fatalf("corrupt manifest: %v", err)
	}

	if _, err := Reconcile(paths, testIdentity, nil); err == nil {
		t.Fatal("Reconcile accepted an invalid current manifest")
	}
	for _, path := range []string{staging, attempt.Dir()} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("reconcile deleted %s under an invalid current: %v", path, err)
		}
	}
}

func TestSelfParentLineageIsRejectedEverywhere(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths) // A -> B -> C, CURRENT=C

	t.Run("mint rejects self-parent", func(t *testing.T) {
		_, err := Mint(paths, testIdentity, MintRequest{
			GenerationID: testGenD,
			Parent:       testGenD,
			Operation:    "test-activation",
			OperationID:  "op-self",
			CreatedAt:    time.Unix(1_753_500_700, 0),
		})
		if err == nil {
			t.Fatal("Mint accepted a self-parent request")
		}
	})

	t.Run("mint rejects nonexistent parent", func(t *testing.T) {
		_, err := Mint(paths, testIdentity, MintRequest{
			GenerationID: testGenD,
			Parent:       "gen-1753500009-99999999",
			Operation:    "test-activation",
			OperationID:  "op-ghost",
			CreatedAt:    time.Unix(1_753_500_701, 0),
		})
		if err == nil {
			t.Fatal("Mint accepted a nonexistent parent; copyNamespaces would silently mint an empty generation")
		}
	})

	t.Run("self-parent manifest fails validation", func(t *testing.T) {
		gen := paths.GenerationPaths(testIdentity, testGenC)
		manifest, err := ReadManifest(gen)
		if err != nil {
			t.Fatalf("ReadManifest() error = %v", err)
		}
		manifest.ParentID = manifest.GenerationID
		if err := WriteManifest(gen, *manifest); err == nil {
			// If writing validated, the read side must still reject it.
			if _, err := ReadManifest(gen); err == nil {
				t.Fatal("self-parent manifest passed both write and read validation")
			}
		}
		// Restore for the rollback subtest below.
		manifest.ParentID = testGenB
		if err := WriteManifest(gen, *manifest); err != nil {
			t.Fatalf("restore manifest: %v", err)
		}
	})

	t.Run("rollback to current is an error not a silent success", func(t *testing.T) {
		if err := RollbackTo(paths, testIdentity, testGenC, time.Unix(1_753_500_702, 0)); err == nil {
			t.Fatal("RollbackTo(current) reported success without moving CURRENT")
		}
		current, err := ReadCurrent(paths, testIdentity)
		if err != nil || current != testGenC {
			t.Fatalf("CURRENT = %s (%v), want unchanged %s", current, err, testGenC)
		}
	})
}
