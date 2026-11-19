// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// withQuarantineCandidateLimits lowers the quarantine candidate limits for one
// test, so the boundary is reachable without tens of thousands of files.
func withQuarantineCandidateLimits(t *testing.T, limits treeLimits) {
	t.Helper()
	saved := quarantineCandidateLimits
	quarantineCandidateLimits = limits
	t.Cleanup(func() { quarantineCandidateLimits = saved })
}

// writeKeyFiles writes n distinct files into dir.
func writeKeyFiles(t *testing.T, dir string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("K%05d.key", i)), []byte("k"), 0o600); err != nil {
			t.Fatalf("write key file %d: %v", i, err)
		}
	}
}

// generatedKeyFiles is a map for mintTestGeneration holding n key files.
func generatedKeyFiles(n int) map[string]string {
	files := make(map[string]string, n)
	for i := 0; i < n; i++ {
		files[fmt.Sprintf("keys/K%05d.key", i)] = "k"
	}
	return files
}

// requireQuarantinedAndReadable checks that every operation that reads
// quarantine still works with generationID quarantined, and that prune then
// removes it.
func requireQuarantinedAndReadable(t *testing.T, paths storepaths.Paths, generationID string) {
	t.Helper()
	if _, err := os.Lstat(paths.QuarantinedGenerationDir(generationID)); err != nil {
		t.Fatalf("generation %s was not quarantined: %v", generationID, err)
	}
	if _, err := ReconcileStoreRoot(paths, testKeyring(t), nil); err != nil {
		t.Fatalf("reconcile after quarantine: %v", err)
	}
	if _, err := InspectStoreRoot(paths, testKeyring(t), nil); err != nil {
		t.Fatalf("inspect after quarantine: %v", err)
	}
	records, err := ListQuarantined(paths)
	if err != nil {
		t.Fatalf("list quarantine: %v", err)
	}
	if len(records) != 1 || records[0].GenerationID != generationID {
		t.Fatalf("quarantine records = %#v, want only %s", records, generationID)
	}
	if err := requireMintableGenerationStore(paths, testKeyring(t)); err != nil {
		t.Fatalf("mint preflight after quarantine: %v", err)
	}
	if _, err := PruneQuarantined(paths, []string{generationID}); err != nil {
		t.Fatalf("prune quarantine: %v", err)
	}
}

// Classification once capped a candidate's inventory files at 4,096 while
// quarantine accounting capped every path in its tree at the same number, so a
// generation of 4,089 to 4,096 members was moved into quarantine and then
// broke reconcile, inspect, list, every mint and prune. Each of these sizes
// must now either stay in place, refused by classification, or be quarantined
// and stay readable.
func TestQuarantineAcceptsOnlyWhatItCanReadBack(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	// The test generation carries three authority files beside its keys.
	for members := 4_088; members <= 4_097; members++ {
		t.Run(fmt.Sprintf("%d members", members), func(t *testing.T) {
			id := fmt.Sprintf("gen-1753501000-%08x", members)
			attempt := mintTestGeneration(t, paths, id, generatedKeyFiles(members-3))

			if _, err := ReconcileStoreRoot(paths, testKeyring(t), nil); err != nil {
				if !strings.Contains(err.Error(), "preserved in place") {
					t.Fatalf("reconcile error = %v, want a classification refusal", err)
				}
				if _, statErr := os.Lstat(attempt.Dir()); statErr != nil {
					t.Fatalf("refused candidate was not preserved in place: %v", statErr)
				}
				if err := os.RemoveAll(attempt.Dir()); err != nil {
					t.Fatal(err)
				}
				return
			}
			requireQuarantinedAndReadable(t, paths, id)
		})
	}
}

// One rule decides both what classification accepts and what quarantine
// accounting reads back: a tree at exactly the entry and byte limits is
// quarantined and stays readable, and one entry or one byte more stays in
// place.
func TestQuarantineCandidateLimitIsOneRuleAtTheBoundary(t *testing.T) {
	build := func(t *testing.T) (storepaths.Paths, treeUsage) {
		t.Helper()
		paths := storepaths.NewPaths(t.TempDir())
		buildGenerationChain(t, paths)
		attempt := mintTestGeneration(t, paths, testGenD, generatedKeyFiles(20))
		usage, err := measureGenerationTree(attempt.Dir(), treeLimits{Entries: 1 << 20, FileBytes: 1 << 20, Bytes: 1 << 30})
		if err != nil {
			t.Fatal(err)
		}
		return paths, usage
	}
	tests := []struct {
		name   string
		limits func(treeUsage) treeLimits
		accept bool
	}{
		{"at both limits", func(u treeUsage) treeLimits {
			return treeLimits{Entries: u.Entries, FileBytes: 1 << 20, Bytes: u.Bytes}
		}, true},
		{"one entry over", func(u treeUsage) treeLimits {
			return treeLimits{Entries: u.Entries - 1, FileBytes: 1 << 20, Bytes: u.Bytes}
		}, false},
		{"one byte over", func(u treeUsage) treeLimits {
			return treeLimits{Entries: u.Entries, FileBytes: 1 << 20, Bytes: u.Bytes - 1}
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths, usage := build(t)
			withQuarantineCandidateLimits(t, tt.limits(usage))
			_, err := ReconcileStoreRoot(paths, testKeyring(t), nil)
			if !tt.accept {
				if err == nil || !strings.Contains(err.Error(), "preserved in place") {
					t.Fatalf("reconcile error = %v, want the candidate preserved in place", err)
				}
				if _, statErr := os.Lstat(paths.GenerationDir(testGenD)); statErr != nil {
					t.Fatalf("refused candidate moved: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("reconcile at the limits: %v", err)
			}
			records, err := ListQuarantined(paths)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0].EntryCount != usage.Entries || records[0].EncodedBytes != usage.Bytes {
				t.Fatalf("quarantine records = %#v, want one measuring %+v", records, usage)
			}
			requireQuarantinedAndReadable(t, paths, testGenD)
		})
	}
}

// Mint refuses, before publishing, a staged tree that quarantine could not
// hold, and a publication at the limits that a failure leaves behind before
// the root replacement is quarantined by the next reconcile.
func TestMintPublishesOnlyWhatQuarantineCanHold(t *testing.T) {
	setup := func(t *testing.T) storepaths.Paths {
		t.Helper()
		paths := storepaths.NewPaths(t.TempDir())
		buildGenerationChain(t, paths)
		// The successor copies the current generation's tree and adds a
		// manifest of its own, so it has as many entries as the current one
		// plus the two files Apply writes.
		current, err := measureGenerationTree(paths.GenerationDir(testGenC), treeLimits{Entries: 1 << 20, FileBytes: 1 << 20, Bytes: 1 << 30})
		if err != nil {
			t.Fatal(err)
		}
		withQuarantineCandidateLimits(t, treeLimits{Entries: current.Entries + 2, FileBytes: 1 << 20, Bytes: 1 << 20})
		return paths
	}
	crash := errors.New("failure after publication")
	request := func(t *testing.T, files int) MintRequest {
		return MintRequest{
			SkipCandidateValidation: true,
			GenerationID:            testGenD, Parent: testGenC, Integrity: testKeyring(t),
			Operation: "test-activation", OperationID: "op-size", CreatedAt: time.Unix(1_753_500_900, 0),
			Apply: func(staged storepaths.GenPaths) error {
				writeKeyFiles(t, staged.KeysDir(), files)
				return nil
			},
			AfterPublication: func() error { return crash },
		}
	}

	t.Run("one entry over", func(t *testing.T) {
		paths := setup(t)
		before := generationNames(t, paths)
		_, err := Mint(paths, request(t, 3))
		if err == nil || !strings.Contains(err.Error(), "does not fit the quarantine candidate limits") {
			t.Fatalf("Mint error = %v, want the size refusal", err)
		}
		if after := generationNames(t, paths); strings.Join(after, ",") != strings.Join(before, ",") {
			t.Fatalf("generations directory changed: %v, was %v", after, before)
		}
		if selectedForTest(t, paths).GenerationID() != testGenC {
			t.Fatal("refused mint changed the selection")
		}
	})
	t.Run("at the limit", func(t *testing.T) {
		paths := setup(t)
		if _, err := Mint(paths, request(t, 2)); !errors.Is(err, crash) {
			t.Fatalf("Mint error = %v, want the injected failure after publication", err)
		}
		if _, err := ReconcileStoreRoot(paths, testKeyring(t), nil); err != nil {
			t.Fatalf("reconcile the abandoned publication: %v", err)
		}
		requireQuarantinedAndReadable(t, paths, testGenD)
	})
}

// writeUnquarantinableTree fills dir with more entries than the old 4,096
// limit and a symlink to target, which classification refuses.
func writeUnquarantinableTree(t *testing.T, dir, target string) {
	t.Helper()
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	writeKeyFiles(t, keys, 4_200)
	if err := os.Symlink(target, filepath.Join(keys, "LINK.key")); err != nil {
		t.Fatal(err)
	}
}

// DiscardAbandoned exists for the generations reconciliation cannot
// quarantine, so it applies no size limit and refuses nothing inside the
// target, and it removes a symlink without following it.
func TestDiscardAbandonedRemovesWhatQuarantineRefuses(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	attempt := mintTestGeneration(t, paths, testGenD, nil)
	writeUnquarantinableTree(t, attempt.Dir(), target)

	if _, err := ReconcileStoreRoot(paths, testKeyring(t), nil); err == nil || !strings.Contains(err.Error(), "preserved in place") {
		t.Fatalf("reconcile error = %v, want the candidate preserved in place", err)
	}
	results, err := DiscardAbandoned(paths, []string{testGenD}, testKeyring(t))
	if err != nil {
		t.Fatalf("DiscardAbandoned() error = %v", err)
	}
	if len(results) != 1 || results[0].AlreadyAbsent || results[0].EncodedBytes == 0 {
		t.Fatalf("DiscardAbandoned() results = %#v", results)
	}
	if _, err := os.Lstat(attempt.Dir()); !os.IsNotExist(err) {
		t.Fatalf("abandoned generation still present: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("discard followed the symlink: %v", err)
	}
	if _, err := ReconcileStoreRoot(paths, testKeyring(t), nil); err != nil {
		t.Fatalf("reconcile after discard: %v", err)
	}
}

// PruneQuarantined likewise applies no size limit, so it removes a quarantine
// entry that quarantine accounting refuses to read.
func TestPruneQuarantinedRemovesWhatAccountingRefuses(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeUnquarantinableTree(t, paths.QuarantinedGenerationDir(testGenD), target)

	if _, err := ListQuarantined(paths); err == nil {
		t.Fatal("ListQuarantined read a quarantine entry holding a symlink")
	}
	results, err := PruneQuarantined(paths, []string{testGenD})
	if err != nil {
		t.Fatalf("PruneQuarantined() error = %v", err)
	}
	if len(results) != 1 || results[0].AlreadyAbsent || results[0].EncodedBytes == 0 {
		t.Fatalf("PruneQuarantined() results = %#v", results)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("prune followed the symlink: %v", err)
	}
	if records, err := ListQuarantined(paths); err != nil || len(records) != 0 {
		t.Fatalf("ListQuarantined() after prune = %#v, %v", records, err)
	}
}

// A selected generation that grew past the limits in place is refused before
// Mint stages anything, so the store pays for no copy or validation, and the
// refusal says what to do.
func TestMintRefusesAParentOverTheLimitsBeforeStaging(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	current, err := measureGenerationTree(paths.GenerationDir(testGenC), treeLimits{Entries: 1 << 20, FileBytes: 1 << 20, Bytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	withQuarantineCandidateLimits(t, treeLimits{Entries: current.Entries - 1, FileBytes: 1 << 20, Bytes: 1 << 20})
	before := generationNames(t, paths)

	staged := false
	_, err = Mint(paths, MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            testGenD, Parent: testGenC, Integrity: testKeyring(t),
		Operation: "test-activation", OperationID: "op-over", CreatedAt: time.Unix(1_753_500_900, 0),
		Apply: func(storepaths.GenPaths) error {
			staged = true
			return nil
		},
	})
	if err == nil || !strings.HasPrefix(err.Error(), "mint preflight: generation "+testGenC+" holds more than one generation may") ||
		!strings.Contains(err.Error(), "prune them from the deleted archive") {
		t.Fatalf("Mint error = %v, want the preflight refusal with its remedy", err)
	}
	if staged {
		t.Fatal("Mint staged and applied before refusing an over-limit parent")
	}
	if after := generationNames(t, paths); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("generations directory changed: %v, was %v", after, before)
	}
}

// The preflight is never stricter than the staged-tree check for a mint that
// adds nothing: a parent whose successor lands exactly on the entry limit,
// with the outgoing seal already written, still mints.
func TestMintPreflightCountsNeitherTheSealNorTwoManifests(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	parent := paths.GenerationPaths(testGenC)
	// Measured before the seal: the successor copies this tree with its own
	// manifest in place of the parent's.
	current, err := measureGenerationTree(parent.Dir(), treeLimits{Entries: 1 << 20, FileBytes: 1 << 20, Bytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSeal(parent, 1_753_500_800, testKeyring(t)); err != nil {
		t.Fatal(err)
	}
	withQuarantineCandidateLimits(t, treeLimits{Entries: current.Entries, FileBytes: 1 << 20, Bytes: 1 << 20})

	if _, err := Mint(paths, MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            testGenD, Parent: testGenC, Integrity: testKeyring(t),
		OutgoingSealAlreadyWritten: true,
		Operation:                  "test-activation", OperationID: "op-exact", CreatedAt: time.Unix(1_753_500_900, 0),
	}); err != nil {
		t.Fatalf("Mint at exactly the entry limit: %v", err)
	}
	if selectedForTest(t, paths).GenerationID() != testGenD {
		t.Fatal("the mint at the limit did not commit")
	}
}
