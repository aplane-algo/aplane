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

// TestMintSealFlipCrashWindowIsRecoverable pins the seal-before-flip crash
// window: Mint seals the outgoing generation immediately before the CURRENT
// flip, so a crash between the two leaves a seal on a generation that is
// still current, plus a published-but-uncommitted successor. The contract:
// the precommit seal is tolerated (nothing consults a seal while its
// generation is current), reconciliation discards the uncommitted successor
// and keeps the seal, and the next flip rewrites the seal from a fresh
// inventory — so later mutation of the still-current generation can never
// poison the rollback chain.
func TestMintSealFlipCrashWindowIsRecoverable(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	const identity = "default"

	g1 := mintSealWindowGeneration(t, paths, identity, MintRequest{
		FirstGeneration: true,
		Operation:       "test-init",
		CreatedAt:       time.Unix(1000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(staged.KeysDir(), "AAA.key"), []byte("k1"), 0o660)
		},
	})
	g1p := paths.GenerationPaths(g1)

	// Fail the CURRENT pointer write: everything up to and including the
	// outgoing generation's seal has happened; the flip has not.
	g2, err := NewGenerationID(time.Unix(2000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpFileSync && filepath.Base(path) == "CURRENT" {
			return errors.New("injected crash before the CURRENT flip")
		}
		return nil
	}
	_, err = Mint(paths, MintRequest{
		GenerationID: g2,
		Parent:       g1,
		Integrity:    testKeyring(t),
		Operation:    "test-op",
		OperationID:  "op-" + g2,
		CreatedAt:    time.Unix(2000, 0),
	})
	fsutil.TestHook = nil
	if err == nil {
		t.Fatal("Mint succeeded despite the injected flip failure")
	}
	if errors.Is(err, ErrCommitDurabilityUnknown) {
		t.Fatalf("the flip never happened; classifying it durability-unknown is wrong: %v", err)
	}

	// The crash-window state: CURRENT names g1, g1 carries a precommit
	// seal, and g2 is published but uncommitted.
	if current, err := ReadCurrent(paths); err != nil || current != g1 {
		t.Fatalf("CURRENT = %q (%v), want %s", current, err, g1)
	}
	if _, err := os.Stat(g1p.SealPath()); err != nil {
		t.Fatalf("outgoing generation's precommit seal missing: %v", err)
	}
	if _, err := os.Stat(paths.GenerationDir(g2)); err != nil {
		t.Fatalf("published uncommitted generation missing: %v", err)
	}
	// The precommit seal must not fail current-generation validation.
	if err := ValidateCurrent(g1p); err != nil {
		t.Fatalf("sealed-but-current generation failed validation: %v", err)
	}

	// Reconciliation discards the uncommitted successor and keeps both the
	// current generation and its precommit seal.
	report, err := Reconcile(paths, nil)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	found := false
	for _, discarded := range report.DiscardedAttempts {
		if discarded == g2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("uncommitted generation %s not discarded: %+v", g2, report)
	}
	if _, err := os.Stat(paths.GenerationDir(g2)); !os.IsNotExist(err) {
		t.Fatalf("uncommitted generation survived reconciliation: %v", err)
	}
	if _, err := os.Stat(g1p.SealPath()); err != nil {
		t.Fatalf("precommit seal removed by reconciliation: %v", err)
	}
	if err := ValidateCurrent(g1p); err != nil {
		t.Fatalf("current generation failed validation after reconcile: %v", err)
	}

	// Mutate the still-current generation: the precommit seal is now stale.
	if err := os.WriteFile(filepath.Join(g1p.KeysDir(), "BBB.key"), []byte("k2"), 0o660); err != nil {
		t.Fatalf("write post-window key: %v", err)
	}

	// The next flip rewrites the seal from a fresh inventory: after this
	// mint, g1's seal must cover the mutation and validate as a rollback
	// target.
	g3 := mintSealWindowGeneration(t, paths, identity, MintRequest{
		Parent:    g1,
		Integrity: testKeyring(t),
		Operation: "test-op-2",
		CreatedAt: time.Unix(3000, 0),
	})
	if current, err := ReadCurrent(paths); err != nil || current != g3 {
		t.Fatalf("CURRENT = %q (%v), want %s", current, err, g3)
	}
	if err := ValidateSealed(g1p, testKeyring(t)); err != nil {
		t.Fatalf("rewritten seal does not cover the post-window mutation: %v", err)
	}

	// The rollback chain survived the whole window.
	if err := RollbackTo(paths, g1, time.Unix(4000, 0), testKeyring(t)); err != nil {
		t.Fatalf("RollbackTo(%s) error = %v", g1, err)
	}
	if current, err := ReadCurrent(paths); err != nil || current != g1 {
		t.Fatalf("CURRENT after rollback = %q (%v), want %s", current, err, g1)
	}
	if err := ValidateCurrent(g1p); err != nil {
		t.Fatalf("rolled-back current generation failed validation: %v", err)
	}
}

func mintSealWindowGeneration(t *testing.T, paths storepaths.Paths, identity string, req MintRequest) string {
	t.Helper()
	id, err := NewGenerationID(req.CreatedAt)
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	req.GenerationID = id
	req.OperationID = req.Operation + "-" + id
	if _, err := Mint(paths, req); err != nil {
		t.Fatalf("Mint(%s): %v", req.Operation, err)
	}
	return id
}
