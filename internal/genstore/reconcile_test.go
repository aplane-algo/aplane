// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
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

func TestMintRequiresParentToBeCurrent(t *testing.T) {
	t.Run("stale parent is rejected", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		buildGenerationChain(t, paths) // A -> B -> C, CURRENT=C
		// Minting with sealed prior A as parent would seal A (again) and
		// flip to D, leaving the real outgoing generation C unsealed for
		// reconciliation to delete as an uncommitted attempt.
		_, err := Mint(paths, testIdentity, MintRequest{
			GenerationID: testGenD,
			Parent:       testGenA,
			Operation:    "test-activation",
			OperationID:  "op-stale",
			CreatedAt:    time.Unix(1_753_500_800, 0),
		})
		if err == nil {
			t.Fatal("Mint accepted a parent that is not the current generation")
		}
		assertChainUntouched(t, paths)
	})

	t.Run("parentless mint on a store with a CURRENT is rejected", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		buildGenerationChain(t, paths)
		_, err := Mint(paths, testIdentity, MintRequest{
			GenerationID: testGenD,
			Operation:    "test-activation",
			OperationID:  "op-parentless",
			CreatedAt:    time.Unix(1_753_500_801, 0),
		})
		if err == nil {
			t.Fatal("Mint accepted a parentless request on a store that already has a current generation")
		}
		assertChainUntouched(t, paths)
	})
}

// assertChainUntouched verifies a rejected mint changed nothing: CURRENT
// still names C, C survives, and no D directory or staging residue exists.
func assertChainUntouched(t *testing.T, paths storepaths.Paths) {
	t.Helper()
	current, err := ReadCurrent(paths, testIdentity)
	if err != nil || current != testGenC {
		t.Fatalf("CURRENT = %s (%v), want unchanged %s", current, err, testGenC)
	}
	if err := ValidateCurrent(paths.GenerationPaths(testIdentity, testGenC)); err != nil {
		t.Fatalf("current generation damaged by rejected mint: %v", err)
	}
	if _, err := os.Lstat(paths.GenerationPaths(testIdentity, testGenD).Dir()); !os.IsNotExist(err) {
		t.Fatalf("rejected mint published generation %s", testGenD)
	}
	entries, err := os.ReadDir(paths.GenerationsDir(testIdentity))
	if err != nil {
		t.Fatalf("ReadDir(generations): %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), storepaths.GenerationStagingPrefix) {
			t.Fatalf("rejected mint left staging residue %s", entry.Name())
		}
	}
}

func TestMintRefusesFirstMintWhenCurrentMissingOnEstablishedStore(t *testing.T) {
	mintD := func(paths storepaths.Paths, first bool) error {
		_, err := Mint(paths, testIdentity, MintRequest{
			GenerationID:    testGenD,
			FirstGeneration: first,
			Operation:       "test-activation",
			OperationID:     "op-relineage",
			CreatedAt:       time.Unix(1_753_500_900, 0),
		})
		return err
	}
	generationsUntouched := func(t *testing.T, paths storepaths.Paths, want []string) {
		t.Helper()
		entries, err := os.ReadDir(paths.GenerationsDir(testIdentity))
		if err != nil {
			t.Fatalf("ReadDir(generations): %v", err)
		}
		var got []string
		for _, entry := range entries {
			got = append(got, entry.Name())
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("generations = %v, want untouched %v", got, want)
		}
	}

	t.Run("unauthorized parentless mint is refused", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
		if err := os.Remove(paths.CurrentPointerPath(testIdentity)); err != nil {
			t.Fatalf("remove CURRENT: %v", err)
		}
		if err := mintD(paths, false); err == nil {
			t.Fatal("Mint accepted a parentless mint without first-generation authorization")
		}
		generationsUntouched(t, paths, []string{testGenA})
	})

	t.Run("authorized first mint refused when generations exist without metadata", func(t *testing.T) {
		// The reviewer's scenario: mint A, remove CURRENT, parentlessly
		// mint D. D must not become current; A must survive.
		paths := storepaths.NewPaths(t.TempDir())
		mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
		if err := os.Remove(paths.CurrentPointerPath(testIdentity)); err != nil {
			t.Fatalf("remove CURRENT: %v", err)
		}
		if err := mintD(paths, true); err == nil {
			t.Fatal("Mint created a new lineage over an established store missing its CURRENT pointer")
		}
		generationsUntouched(t, paths, []string{testGenA})
	})

	t.Run("authorized first mint refused when metadata carries the layout marker", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		if err := fsutil.MkdirAll(paths.KeystoreMetadataDir(testIdentity)); err != nil {
			t.Fatalf("MkdirAll(metadata): %v", err)
		}
		if _, _, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(testIdentity), []byte("pw")); err != nil {
			t.Fatalf("CreateKeystoreMetadata() error = %v", err)
		}
		mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
		if err := os.Remove(paths.CurrentPointerPath(testIdentity)); err != nil {
			t.Fatalf("remove CURRENT: %v", err)
		}
		if err := mintD(paths, true); err == nil {
			t.Fatal("Mint created a new lineage over a marked generational store missing its CURRENT pointer")
		}
		generationsUntouched(t, paths, []string{testGenA})
	})

	t.Run("authorized first mint refused when sealed history exists", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		buildGenerationChain(t, paths) // A, B sealed; C current
		if err := os.Remove(paths.CurrentPointerPath(testIdentity)); err != nil {
			t.Fatalf("remove CURRENT: %v", err)
		}
		if err := mintD(paths, true); err == nil {
			t.Fatal("Mint created a new lineage over sealed generational history")
		}
		generationsUntouched(t, paths, []string{testGenA, testGenB, testGenC})
	})
}

func TestInspectClassifiesWithoutDeleting(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	attempt := paths.GenerationPaths(testIdentity, testGenD)
	for _, namespace := range []string{"keys", "keytypes"} {
		if err := os.MkdirAll(filepath.Join(attempt.Dir(), namespace), 0o770); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	staging := filepath.Join(paths.GenerationsDir(testIdentity), storepaths.GenerationStagingPrefix+"leftover")
	if err := os.MkdirAll(staging, 0o770); err != nil {
		t.Fatalf("MkdirAll(staging): %v", err)
	}

	report, err := Inspect(paths, testIdentity, nil)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !slices.Equal(report.DiscardedAttempts, []string{testGenD}) || len(report.DiscardedStaging) != 1 {
		t.Fatalf("classification = %v/%v, want the attempt and staging residue reported", report.DiscardedAttempts, report.DiscardedStaging)
	}
	// Nothing was deleted.
	for _, path := range []string{attempt.Dir(), staging} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Inspect deleted %s: %v", path, err)
		}
	}
	// Reconcile still deletes the same set.
	if _, err := Reconcile(paths, testIdentity, nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	for _, path := range []string{attempt.Dir(), staging} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("Reconcile left %s behind: %v", path, err)
		}
	}
}

func TestReconcileReconfirmsCurrentFlipDurability(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)

	identityDirSynced := false
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == paths.IdentityDir(testIdentity) {
			identityDirSynced = true
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	if _, err := Reconcile(paths, testIdentity, nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if !identityDirSynced {
		t.Fatal("Reconcile did not fsync the identity directory; an ErrCommitDurabilityUnknown flip would never be re-confirmed")
	}

	// The read-only classification must not perform the sync.
	identityDirSynced = false
	if _, err := Inspect(paths, testIdentity, nil); err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if identityDirSynced {
		t.Fatal("Inspect performed a durability sync; it must stay read-only")
	}
}

func TestMintPreservesStoreModesUnderUmask(t *testing.T) {
	oldUmask := syscall.Umask(0o022)
	defer syscall.Umask(oldUmask)

	paths := storepaths.NewPaths(t.TempDir())
	mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	// Normalize the source file mode; the child copy must preserve it
	// exactly despite the restrictive umask.
	firstKey := filepath.Join(paths.GenerationPaths(testIdentity, testGenA).KeysDir(), "A.key")
	if err := os.Chmod(firstKey, 0o660); err != nil {
		t.Fatalf("chmod source key: %v", err)
	}
	if _, err := Mint(paths, testIdentity, MintRequest{
		GenerationID: testGenB,
		Parent:       testGenA,
		Operation:    "test-activation",
		OperationID:  "op-umask",
		CreatedAt:    time.Unix(1_754_200_000, 0),
	}); err != nil {
		t.Fatalf("Mint(child) error = %v", err)
	}

	child := paths.GenerationPaths(testIdentity, testGenB)
	for _, dir := range []string{child.KeysDir(), child.KeyTypeRecordsDir()} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if perm := info.Mode().Perm(); perm != 0o770 {
			t.Fatalf("namespace dir %s mode = %o, want 770 despite umask", dir, perm)
		}
	}
	info, err := os.Stat(filepath.Join(child.KeysDir(), "A.key"))
	if err != nil {
		t.Fatalf("stat copied key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Fatalf("copied key mode = %o, want source mode 660 despite umask", perm)
	}
}

func TestSealTempResidueIsToleratedAndCollected(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	gen := paths.GenerationPaths(testIdentity, testGenC)
	residue := filepath.Join(gen.Dir(), storepaths.GenerationSealName+".tmp-123456")
	if err := os.WriteFile(residue, []byte("partial seal"), 0o660); err != nil {
		t.Fatalf("write residue: %v", err)
	}

	// The survivable crash is absorbed: validation tolerates the residue
	// instead of sending the store into recovery.
	if err := ValidateCurrent(gen); err != nil {
		t.Fatalf("ValidateCurrent() error = %v, want tolerance for durable-write residue", err)
	}
	report, err := Inspect(paths, testIdentity, nil)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !slices.Contains(report.DiscardedStaging, filepath.Base(residue)) {
		t.Fatalf("Inspect classification %v does not report the residue", report.DiscardedStaging)
	}
	if _, err := os.Stat(residue); err != nil {
		t.Fatalf("Inspect deleted the residue: %v", err)
	}

	if _, err := Reconcile(paths, testIdentity, nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, err := os.Stat(residue); !os.IsNotExist(err) {
		t.Fatalf("Reconcile left the residue behind: %v", err)
	}
}

func TestMintRefusesMissingParentNamespace(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	// Damage the current (= parent) generation after it committed.
	if err := os.RemoveAll(paths.GenerationPaths(testIdentity, testGenA).KeysDir()); err != nil {
		t.Fatalf("remove parent keys namespace: %v", err)
	}

	_, err := Mint(paths, testIdentity, MintRequest{
		GenerationID: testGenB,
		Parent:       testGenA,
		Operation:    "test-activation",
		OperationID:  "op-damaged-parent",
		CreatedAt:    time.Unix(1_754_200_100, 0),
	})
	if err == nil {
		t.Fatal("Mint silently propagated a damaged parent: child would commit with an empty keys namespace")
	}
	if _, statErr := os.Lstat(paths.GenerationPaths(testIdentity, testGenB).Dir()); !os.IsNotExist(statErr) {
		t.Fatalf("rejected mint published a generation: %v", statErr)
	}
}

func TestCrashedPruneRetriesAsNoOp(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths) // A, B sealed priors; C current
	// Simulate a prune that crashed after the tombstone rename but before
	// the removal finished: the doomed generation sits half-deleted under
	// a staging name.
	doomed := paths.GenerationPaths(testIdentity, testGenA).Dir()
	tombstone := filepath.Join(paths.GenerationsDir(testIdentity), storepaths.GenerationStagingPrefix+"prune-"+testGenA)
	if err := os.Rename(doomed, tombstone); err != nil {
		t.Fatalf("simulate crashed prune: %v", err)
	}
	if err := os.Remove(filepath.Join(tombstone, storepaths.GenerationSealName)); err != nil {
		t.Fatalf("simulate partial deletion: %v", err)
	}

	// The retry neither wedges on the residue nor misclassifies it: the
	// tombstone is staging garbage, and the remaining prior still prunes.
	removed, err := CollectGarbage(paths, testIdentity, nil, false)
	if err != nil {
		t.Fatalf("CollectGarbage(retry) error = %v, want crash-idempotent retry", err)
	}
	if !slices.Equal(removed, []string{testGenB}) {
		t.Fatalf("removed = %v, want [%s]", removed, testGenB)
	}
	if _, err := os.Stat(tombstone); !os.IsNotExist(err) {
		t.Fatalf("tombstone residue survived reconciliation: %v", err)
	}
	entries, err := os.ReadDir(paths.GenerationsDir(testIdentity))
	if err != nil || len(entries) != 1 {
		t.Fatalf("generations after retry = %d (%v), want only current", len(entries), err)
	}
}

func TestManifestRejectsTrailingGarbage(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	gen := paths.GenerationPaths(testIdentity, testGenA)
	data, err := os.ReadFile(gen.ManifestPath())
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := os.WriteFile(gen.ManifestPath(), append(data, []byte("{\"extra\":1}")...), 0o660); err != nil {
		t.Fatalf("append garbage: %v", err)
	}
	if _, err := ReadManifest(gen); err == nil {
		t.Fatal("ReadManifest accepted trailing data after the JSON document")
	}
}

func TestMintRejectsStagedSeal(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
	// An Apply hook that plants a seal in the staged generation: a staged
	// generation is pre-publish by definition and must never carry the
	// final content record.
	_, err := Mint(paths, testIdentity, MintRequest{
		GenerationID: testGenB,
		Parent:       testGenA,
		Operation:    "test-activation",
		OperationID:  "op-staged-seal",
		CreatedAt:    time.Unix(1_754_300_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			return os.WriteFile(staged.SealPath(), []byte("{}"), 0o660)
		},
	})
	if err == nil {
		t.Fatal("Mint accepted a staged generation carrying a seal")
	}
}

func TestReconcileCollectsNamespaceDurableWriteResidue(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	gen := paths.GenerationPaths(testIdentity, testGenC)
	residue := filepath.Join(gen.KeysDir(), "ADDR.key.tmp-998877")
	if err := os.WriteFile(residue, []byte("partial write"), 0o660); err != nil {
		t.Fatalf("write residue: %v", err)
	}

	report, err := Reconcile(paths, testIdentity, nil)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if !slices.Contains(report.DiscardedStaging, filepath.Base(residue)) {
		t.Fatalf("residue not reported: %v", report.DiscardedStaging)
	}
	if _, err := os.Stat(residue); !os.IsNotExist(err) {
		t.Fatalf("namespace durable-write residue survived reconciliation; it would be copied and sealed into every child generation: %v", err)
	}
}

// TestReconcileKeepsRecordsWhoseNamesMerelyContainTmpDash pins the residue
// matcher to the exact temp-file shape (".tmp-" + digits suffix). A substring
// match would silently delete a structurally valid record whose own name
// contains ".tmp-".
func TestReconcileKeepsRecordsWhoseNamesMerelyContainTmpDash(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	gen := paths.GenerationPaths(testIdentity, testGenC)
	kept := []string{
		filepath.Join(gen.KeyTypeRecordsDir(), "custom.tmp-v2.template"),
		filepath.Join(gen.KeysDir(), "weird.tmp-name.key"),
		filepath.Join(gen.KeysDir(), "trailing.tmp-"),
	}
	for _, path := range kept {
		if err := os.WriteFile(path, []byte("legitimate record"), 0o660); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	report, err := Reconcile(paths, testIdentity, nil)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	for _, path := range kept {
		if slices.Contains(report.DiscardedStaging, filepath.Base(path)) {
			t.Fatalf("legitimate record %s classified as residue", filepath.Base(path))
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("legitimate record %s deleted by reconciliation: %v", filepath.Base(path), err)
		}
	}
}
