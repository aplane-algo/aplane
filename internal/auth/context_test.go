// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/productmode"
)

func TestContextWithIdentity_RoundTrip(t *testing.T) {
	identity := &Identity{
		ID:     "test-user",
		Type:   "service",
		Method: "aplane-token",
	}

	ctx := ContextWithIdentity(context.Background(), identity)
	got := IdentityFromContext(ctx)

	switch {
	case got == nil:
		t.Fatal("expected identity, got nil")
	case got.ID != "test-user":
		t.Errorf("expected ID 'test-user', got %q", got.ID)
	case got.Type != "service":
		t.Errorf("expected Type 'service', got %q", got.Type)
	case got.Method != "aplane-token":
		t.Errorf("expected Method 'aplane-token', got %q", got.Method)
	}
}

func TestIdentityFromContext_EmptyContext(t *testing.T) {
	got := IdentityFromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil identity from empty context, got %+v", got)
	}
}

func TestNewDefaultIdentity(t *testing.T) {
	id := NewDefaultIdentity("ipc-passphrase")

	if id.ID != productmode.IdentityID {
		t.Errorf("expected ID %q, got %q", productmode.IdentityID, id.ID)
	}
	if id.Type != "service" {
		t.Errorf("expected Type 'service', got %q", id.Type)
	}
	if id.Method != "ipc-passphrase" {
		t.Errorf("expected Method 'ipc-passphrase', got %q", id.Method)
	}
}
