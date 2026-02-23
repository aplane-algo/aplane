// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/aplane-algo/aplane/internal/util"
)

// AuthScheme is the authentication scheme used in the Authorization header.
// Per RFC 7235, scheme comparison is case-insensitive.
const AuthScheme = "aplane"

// TokenAuthenticator validates requests using bearer token authentication
type TokenAuthenticator struct {
	expectedToken string
}

// NewTokenAuthenticator creates a new token authenticator
func NewTokenAuthenticator(expectedToken string) *TokenAuthenticator {
	return &TokenAuthenticator{
		expectedToken: expectedToken,
	}
}

// Authenticate validates the Authorization: aplane <token> header.
// The scheme comparison is case-insensitive per RFC 7235.
func (t *TokenAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, ErrNoCredentials
	}

	scheme, token, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, AuthScheme) || token == "" {
		return nil, ErrInvalidCredentials
	}

	if !util.ValidateToken(token, t.expectedToken) {
		return nil, ErrInvalidCredentials
	}

	return &Identity{
		ID:     DefaultIdentityID,
		Type:   "service",
		Method: t.Method(),
	}, nil
}

// Method returns the authentication method name
func (t *TokenAuthenticator) Method() string {
	return "aplane-token"
}

// Compile-time interface check
var _ Authenticator = (*TokenAuthenticator)(nil)
