// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package auth

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestTokenAuthenticator_Success(t *testing.T) {
	token := "test-token-12345"
	auth := NewTokenAuthenticator(token)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "aplane "+token)

	identity, err := auth.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if identity == nil {
		t.Fatal("expected identity, got nil")
	}

	if identity.ID != DefaultIdentityID {
		t.Errorf("expected ID %q, got %q", DefaultIdentityID, identity.ID)
	}

	if identity.Type != "service" {
		t.Errorf("expected type 'service', got %q", identity.Type)
	}

	if identity.Method != "aplane-token" {
		t.Errorf("expected method 'aplane-token', got %q", identity.Method)
	}
}

func TestTokenAuthenticator_MissingHeader(t *testing.T) {
	auth := NewTokenAuthenticator("test-token")

	req := httptest.NewRequest("GET", "/test", nil)

	_, err := auth.Authenticate(context.Background(), req)
	if err != ErrNoCredentials {
		t.Errorf("expected ErrNoCredentials, got %v", err)
	}
}

func TestTokenAuthenticator_InvalidToken(t *testing.T) {
	auth := NewTokenAuthenticator("correct-token")

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "aplane wrong-token")

	_, err := auth.Authenticate(context.Background(), req)
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestTokenAuthenticator_Method(t *testing.T) {
	auth := NewTokenAuthenticator("token")
	if auth.Method() != "aplane-token" {
		t.Errorf("expected method 'aplane-token', got %q", auth.Method())
	}
}

func TestTokenAuthenticator_CaseInsensitiveScheme(t *testing.T) {
	token := "test-token-12345"
	auth := NewTokenAuthenticator(token)

	for _, scheme := range []string{"aplane", "Aplane", "APLANE", "APlane"} {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", scheme+" "+token)

		identity, err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Errorf("scheme %q: expected no error, got %v", scheme, err)
			continue
		}
		if identity == nil {
			t.Errorf("scheme %q: expected identity, got nil", scheme)
		}
	}
}

func TestTokenAuthenticator_WrongScheme(t *testing.T) {
	auth := NewTokenAuthenticator("test-token")

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	_, err := auth.Authenticate(context.Background(), req)
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestTokenAuthenticator_MalformedHeader(t *testing.T) {
	auth := NewTokenAuthenticator("test-token")

	cases := []struct {
		name  string
		value string
	}{
		{"scheme only", "aplane"},
		{"scheme with trailing space", "aplane "},
		{"empty token", "aplane  "},
	}

	for _, tc := range cases {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", tc.value)

		_, err := auth.Authenticate(context.Background(), req)
		if err != ErrInvalidCredentials {
			t.Errorf("%s: expected ErrInvalidCredentials, got %v", tc.name, err)
		}
	}
}
