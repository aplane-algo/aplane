// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import "testing"

func TestTokenAuthenticatorGenerationIncrementsOnUpdate(t *testing.T) {
	ta := NewTokenAuthenticator("old-token")

	gen, ok := ta.ValidateTokenGeneration("old-token")
	if !ok {
		t.Fatal("old token did not validate")
	}
	if gen != 1 {
		t.Fatalf("initial generation = %d, want 1", gen)
	}

	ta.UpdateToken("new-token")

	if _, ok := ta.ValidateTokenGeneration("old-token"); ok {
		t.Fatal("old token validated after update")
	}
	gen, ok = ta.ValidateTokenGeneration("new-token")
	if !ok {
		t.Fatal("new token did not validate")
	}
	if gen != 2 {
		t.Fatalf("generation after update = %d, want 2", gen)
	}
	if ta.Generation() != 2 {
		t.Fatalf("Generation() = %d, want 2", ta.Generation())
	}
}
