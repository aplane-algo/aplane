// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// AuthScheme is the authentication scheme used in the Authorization header.
// Per RFC 7235, scheme comparison is case-insensitive.
const AuthScheme = "aplane"

// TokenAuthenticator validates requests using bearer token authentication.
// Thread-safe: the token can be updated at runtime (e.g., revocation).
type TokenAuthenticator struct {
	mu            sync.RWMutex
	expectedToken string
	generation    uint64
}

// NewTokenAuthenticator creates a new token authenticator
func NewTokenAuthenticator(expectedToken string) *TokenAuthenticator {
	return &TokenAuthenticator{
		expectedToken: expectedToken,
		generation:    1,
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

	t.mu.RLock()
	valid := tokenfile.ValidateToken(token, t.expectedToken)
	t.mu.RUnlock()

	if !valid {
		return nil, ErrInvalidCredentials
	}

	return NewProductIdentity(t.Method()), nil
}

// ValidateToken checks whether the given token matches the expected token.
// Uses constant-time comparison. Thread-safe.
func (t *TokenAuthenticator) ValidateToken(token string) bool {
	_, valid := t.ValidateTokenGeneration(token)
	return valid
}

// ValidateTokenGeneration checks whether the token matches and returns the
// token generation observed during validation. The generation lets callers close
// connections that authenticated before a later token rotation.
func (t *TokenAuthenticator) ValidateTokenGeneration(token string) (uint64, bool) {
	t.mu.RLock()
	valid := tokenfile.ValidateToken(token, t.expectedToken)
	generation := t.generation
	t.mu.RUnlock()
	return generation, valid
}

// ComputeHMACPair computes two SHA-256 HMACs from one token-generation
// snapshot. SSH mutual authentication uses the pair for its independently
// domain-separated server and client proofs without exposing the raw token.
func (t *TokenAuthenticator) ComputeHMACPair(firstMessage, secondMessage []byte) (firstMAC, secondMAC []byte, generation uint64, ok bool) {
	if len(firstMessage) == 0 || len(secondMessage) == 0 {
		return nil, nil, 0, false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.expectedToken == "" {
		return nil, nil, 0, false
	}

	firstMAC = computeHMACSHA256(t.expectedToken, firstMessage)
	secondMAC = computeHMACSHA256(t.expectedToken, secondMessage)
	return firstMAC, secondMAC, t.generation, true
}

func computeHMACSHA256(token string, message []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

// UpdateToken replaces the expected token. Used for token revocation.
func (t *TokenAuthenticator) UpdateToken(newToken string) {
	t.mu.Lock()
	t.expectedToken = newToken
	t.generation++
	t.mu.Unlock()
}

// Generation returns the current token generation.
func (t *TokenAuthenticator) Generation() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.generation
}

// Method returns the authentication method name
func (t *TokenAuthenticator) Method() string {
	return "aplane-token"
}

// Compile-time interface check
var _ Authenticator = (*TokenAuthenticator)(nil)
