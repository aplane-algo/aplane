// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package auth provides authentication interfaces and the identity model.
//
// An HTTP request is authenticated by the connection it arrived on: the SSH
// tunnel verified an enrolled key and the HTTP server attached that key's
// fingerprint to the connection context. Admin sessions over local IPC are
// authenticated by the store passphrase. Requests carry no credential.
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

	// Method is the authentication method used ("ssh-key", "ipc-passphrase")
	Method string

	// Role selects the identity's permissions. It is assigned by the trusted
	// authentication path; empty or unknown roles are denied.
	Role string

	// KeyFingerprint is the SHA256 fingerprint of the SSH key that
	// authenticated a client identity.
	KeyFingerprint string

	// Label is the display label of an enrolled client key: information for
	// operators, never authority.
	Label string

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
