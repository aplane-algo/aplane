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

	candidate, err := classifyQuarantineCandidate(gen)
	if err != nil {
		t.Fatalf("classifyQuarantineCandidate() error = %v", err)
	}
	if candidate.GenerationID != testGenA || candidate.ParentID != "" {
		t.Fatalf("candidate identity = %#v", candidate)
	}
	if !candidate.AtMintInventoryMatch {
		t.Fatal("exact at-mint publication classified as diverged")
	}
	if candidate.EntryCount != 3 {
		t.Fatalf("EntryCount = %d, want manifest plus two members", candidate.EntryCount)
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

	candidate, err := classifyQuarantineCandidate(gen)
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

	candidate, err := classifyQuarantineCandidate(gen)
	if err != nil {
		t.Fatalf("unknown future term prevented safe classification: %v", err)
	}
	if candidate.AtMintInventoryMatch {
		t.Fatal("future-term mutation unexpectedly matches at-mint inventory")
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

	_, err := classifyQuarantineCandidate(gen)
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

	if _, err := classifyQuarantineCandidate(gen); err == nil {
		t.Fatal("classifyQuarantineCandidate accepted a symlinked member")
	}
}
