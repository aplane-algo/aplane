// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package genstoretest provides test fixtures for generation-based stores.
package genstoretest

import (
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// MintFirst mints an identity's first (empty) generation the way initialize
// does, so tests operate on the only supported store layout. Idempotent.
func MintFirst(t testing.TB, paths storepaths.Paths, identityID string) {
	t.Helper()
	if _, err := genstore.ReadCurrent(paths, identityID); err == nil {
		return
	}
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(paths, identityID, genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "store-initialize",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_785_200_000, 0),
	}); err != nil {
		t.Fatalf("Mint(first generation): %v", err)
	}
}
