// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package auth provides authentication interfaces and implementations.
//
// This package defines the Authenticator interface used for validating
// requests and returning authenticated identities. Implementations include
// bearer token authentication, with future support for mTLS and OIDC.
package auth

import (
	"context"
	"errors"
	"net/http"
)

// Common authentication errors
var (
	// ErrNoCredentials indicates no authentication credentials were provided
	ErrNoCredentials = errors.New("no authentication credentials provided")

	// ErrInvalidCredentials indicates the provided credentials are invalid
	ErrInvalidCredentials = errors.New("invalid authentication credentials")
)

// Identity represents an authenticated entity
type Identity struct {
	// ID is a unique identifier for this identity (user ID, service account, etc.)
	ID string

	// Type indicates the kind of identity ("user", "service", "admin")
	Type string

	// Method is the authentication method used ("aplane-token", "mtls", "oidc")
	Method string

	// Metadata contains additional claims or attributes
	Metadata map[string]string
}

// Authenticator validates requests and returns the authenticated identity
type Authenticator interface {
	// Authenticate validates the request and returns the identity.
	// Returns ErrNoCredentials if no credentials are present.
	// Returns ErrInvalidCredentials if credentials are invalid.
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)

	// Method returns the authentication method name (for logging/debugging)
	Method() string
}
