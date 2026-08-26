// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestClassifyQuarantineCandidateRecordsExactAtMintMatch(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/ACCOUNT.key":         "credential",
		"keytypes/example.v1.json": "{}\n",
	})

	candidate, err := classifyQuarantineCandidate(gen, nil)
	if err != nil {
		t.Fatalf("classifyQuarantineCandidate() error = %v", err)
	}
	if candidate.GenerationID != testGenA || candidate.ParentID != "" {
		t.Fatalf("candidate identity = %#v", candidate)
	}
	if !candidate.AtMintInventoryMatch {
		t.Fatal("exact at-mint publication classified as diverged")
	}
	if candidate.EntryCount != 6 {
		t.Fatalf("EntryCount = %d, want manifest plus five authority members", candidate.EntryCount)
	}
	if candidate.ManifestSHA256 == "" || candidate.LiveInventorySHA256 == "" {
		t.Fatalf("candidate digests are incomplete: %#v", candidate)
	}
}

func TestClassifyQuarantineCandidateAllowsPostMintMutation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/ACCOUNT.key": "at-mint",
	})
	if err := os.WriteFile(
		filepath.Join(gen.KeysDir(), "ACCOUNT.key"),
		[]byte("legitimate later current-state mutation"),
		0o600,
	); err != nil {
		t.Fatalf("mutate current-state member: %v", err)
	}

	candidate, err := classifyQuarantineCandidate(gen, nil)
	if err != nil {
		t.Fatalf("classifyQuarantineCandidate(mutated) error = %v", err)
	}
	if candidate.AtMintInventoryMatch {
		t.Fatal("post-mint mutation unexpectedly matches at-mint inventory")
	}
}

func TestClassifyQuarantineCandidateDoesNotRequireTermKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/ACCOUNT.key": "at-mint",
	})
	future := cryptotest.KeyringAtTerm(t, 9, bytes.Repeat([]byte{0x91}, 32))
	sealed, err := future.Seal([]byte("future authority"), crypto.AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatalf("Seal(future term): %v", err)
	}
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "ACCOUNT.key"), sealed, 0o600); err != nil {
		t.Fatalf("write future-term member: %v", err)
	}

	current := testKeyring(t)
	candidate, err := classifyQuarantineCandidate(gen, current)
	if err != nil {
		t.Fatalf("unknown future term prevented safe classification: %v", err)
	}
	if candidate.AtMintInventoryMatch {
		t.Fatal("future-term mutation unexpectedly matches at-mint inventory")
	}
	if candidate.TermValidation.TermUnavailable != 1 || candidate.TermValidation.Failed != 0 {
		t.Fatalf("future-term validation = %+v", candidate.TermValidation)
	}
}

func TestClassifyQuarantineCandidateRecordsKnownTermVerificationFailureWithoutBlocking(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/ACCOUNT.key": "at-mint",
	})
	kr := testKeyring(t)
	sealed, err := kr.Seal([]byte("credential"), crypto.AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-2] ^= 1
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "ACCOUNT.key"), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := classifyQuarantineCandidate(gen, kr)
	if err != nil {
		t.Fatalf("known-term integrity failure blocked safe relocation: %v", err)
	}
	if candidate.TermValidation.Failed != 1 || candidate.TermValidation.Verified != 0 {
		t.Fatalf("term validation = %+v", candidate.TermValidation)
	}
}

func TestClassifyQuarantineCandidateRecordsKnownTermVerification(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/ACCOUNT.key": "at-mint",
	})
	kr := testKeyring(t)
	sealed, err := kr.Seal([]byte("credential"), crypto.AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "ACCOUNT.key"), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := classifyQuarantineCandidate(gen, kr)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.TermValidation.Verified != 1 || candidate.TermValidation.Failed != 0 {
		t.Fatalf("term validation = %+v", candidate.TermValidation)
	}
}

func TestClassifyQuarantineCandidateRejectsOversizedFileBeforeReadingIt(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/ACCOUNT.key": "at-mint",
	})
	path := filepath.Join(gen.KeysDir(), "ACCOUNT.key")
	if err := os.Truncate(path, quarantineCandidateMaxFileBytes+1); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	_, err := classifyQuarantineCandidate(gen, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("oversized candidate error = %v, want bounded-read rejection", err)
	}
}

func TestClassifyQuarantineCandidateRejectsSymlink(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, nil)
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(gen.KeysDir(), "ACCOUNT.key")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if _, err := classifyQuarantineCandidate(gen, nil); err == nil {
		t.Fatal("classifyQuarantineCandidate accepted a symlinked member")
	}
}

func TestPruneQuarantinedRemovesOnlySelectedQuarantineState(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	mintTestGeneration(t, paths, testGenD, map[string]string{
		"keys/ACCOUNT.key": "candidate",
	})
	if _, err := ReconcileStoreRoot(paths, testKeyring(t), nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	results, err := PruneQuarantined(paths, []string{testGenD})
	if err != nil {
		t.Fatalf("PruneQuarantined() error = %v", err)
	}
	if len(results) != 1 || results[0].GenerationID != testGenD ||
		results[0].AlreadyAbsent || results[0].EncodedBytes == 0 {
		t.Fatalf("PruneQuarantined() results = %#v", results)
	}
	if _, err := os.Stat(paths.QuarantinedGenerationDir(testGenD)); !os.IsNotExist(err) {
		t.Fatalf("selected quarantine generation survived prune: %v", err)
	}
	for _, id := range []string{testGenA, testGenB, testGenC} {
		if _, err := os.Stat(paths.GenerationDir(id)); err != nil {
			t.Fatalf("authoritative generation %s changed during quarantine prune: %v", id, err)
		}
	}

	results, err = PruneQuarantined(paths, []string{testGenD})
	if err != nil {
		t.Fatalf("PruneQuarantined(retry) error = %v", err)
	}
	if len(results) != 1 || !results[0].AlreadyAbsent {
		t.Fatalf("PruneQuarantined(retry) results = %#v, want already absent", results)
	}
}

func TestListQuarantinedReturnsNonAuthoritativeMetadata(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	mintTestGeneration(t, paths, testGenD, map[string]string{
		"keys/ACCOUNT.key": "candidate",
	})
	if _, err := ReconcileStoreRoot(paths, testKeyring(t), nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	records, err := ListQuarantined(paths)
	if err != nil {
		t.Fatalf("ListQuarantined() error = %v", err)
	}
	if len(records) != 1 || records[0].GenerationID != testGenD || records[0].EncodedBytes == 0 {
		t.Fatalf("ListQuarantined() = %#v", records)
	}
	if _, err := os.Stat(paths.GenerationDir(testGenD)); !os.IsNotExist(err) {
		t.Fatalf("listing quarantine changed active namespace: %v", err)
	}
}

func TestPruneQuarantinedValidatesEntireSelectionBeforeDeleting(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.QuarantinedGenerationDir(testGenD), 0o700); err != nil {
		t.Fatalf("MkdirAll(quarantine): %v", err)
	}
	if _, err := PruneQuarantined(paths, []string{testGenD, "../escape"}); err == nil {
		t.Fatal("PruneQuarantined accepted an unsafe generation ID")
	}
	if _, err := os.Stat(paths.QuarantinedGenerationDir(testGenD)); err != nil {
		t.Fatalf("valid target was deleted before full request validation: %v", err)
	}
}

func TestPruneQuarantinedCannotDeleteActiveGeneration(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	buildGenerationChain(t, paths)
	results, err := PruneQuarantined(paths, []string{testGenC})
	if err != nil {
		t.Fatalf("PruneQuarantined(active ID) error = %v", err)
	}
	if len(results) != 1 || !results[0].AlreadyAbsent {
		t.Fatalf("PruneQuarantined(active ID) = %#v, want absent quarantine target", results)
	}
	if _, err := os.Stat(paths.GenerationDir(testGenC)); err != nil {
		t.Fatalf("active generation was affected by quarantine prune: %v", err)
	}
}
