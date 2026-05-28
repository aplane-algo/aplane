// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import (
	"context"
	"errors"
	"testing"
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

	if id.ID != DefaultIdentityID {
		t.Errorf("expected ID %q, got %q", DefaultIdentityID, id.ID)
	}
	if id.Type != "service" {
		t.Errorf("expected Type 'service', got %q", id.Type)
	}
	if id.Method != "ipc-passphrase" {
		t.Errorf("expected Method 'ipc-passphrase', got %q", id.Method)
	}
}

func TestDefaultIdentityID(t *testing.T) {
	if DefaultIdentityID != "default" {
		t.Errorf("expected DefaultIdentityID to be 'default', got %q", DefaultIdentityID)
	}
}

func TestCurrentProductIdentityID(t *testing.T) {
	if CurrentProductIdentityID() != DefaultIdentityID {
		t.Errorf("expected CurrentProductIdentityID to be %q, got %q", DefaultIdentityID, CurrentProductIdentityID())
	}
}

func TestIsCurrentProductIdentity(t *testing.T) {
	if !IsCurrentProductIdentity(DefaultIdentityID) {
		t.Fatalf("expected %q to be recognized as current product identity", DefaultIdentityID)
	}
	if IsCurrentProductIdentity("other-identity") {
		t.Fatal("expected non-product identity to be rejected")
	}
}

func TestRequireCurrentProductIdentity(t *testing.T) {
	if err := RequireCurrentProductIdentity(DefaultIdentityID); err != nil {
		t.Fatalf("expected current product identity to pass, got %v", err)
	}

	err := RequireCurrentProductIdentity("other-identity")
	if err == nil {
		t.Fatal("expected non-product identity to fail")
	}
	if !errors.Is(err, ErrUnsupportedProductIdentity) {
		t.Fatalf("expected ErrUnsupportedProductIdentity, got %v", err)
	}
}
