// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package genstoretest provides test fixtures for generation-based stores.
package genstoretest

import (
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// MintFirst mints an identity's first (empty) generation the way initialize
// does, so tests operate on the only supported store layout. Idempotent.
func MintFirst(t testing.TB, paths storepaths.Paths) {
	t.Helper()
	if _, err := genstore.ReadCurrent(paths); err == nil {
		return
	}
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "store-initialize",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_785_200_000, 0),
		Apply:           ApplyAuthorityPlaceholders,
	}); err != nil {
		t.Fatalf("Mint(first generation): %v", err)
	}
}

// ApplyAuthorityPlaceholders supplies structurally complete, deliberately
// unauthenticated authority members to low-level tests that do not exercise
// policy or node-role verification. Production initialization must create
// authenticated members with policy and noderole APIs instead.
func ApplyAuthorityPlaceholders(staged storepaths.GenPaths) error {
	for _, path := range []string{
		staged.PolicyPath(),
		staged.PolicyIntegritySidecar(),
		staged.NodeRoleIntegritySidecar(),
	} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Active resolves an identity's current generation for tests that exercise an
// API whose caller already owns active-path resolution.
func Active(t testing.TB, paths storepaths.Paths) storepaths.ActivePaths {
	t.Helper()
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active
}
