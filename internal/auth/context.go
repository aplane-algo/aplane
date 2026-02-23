// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package auth

import "context"

// DefaultIdentityID is the identity used for single-tenant deployments.
const DefaultIdentityID = "default"

// contextKey is an unexported type for context keys in this package.
type contextKey struct{}

// identityKey is the context key for the authenticated identity.
var identityKey = contextKey{}

// ContextWithIdentity returns a new context carrying the given identity.
func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// IdentityFromContext extracts the authenticated identity from the context.
// Returns nil if no identity is present.
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

// NewDefaultIdentity returns an Identity with ID "default" and the given auth method.
func NewDefaultIdentity(method string) *Identity {
	return &Identity{
		ID:     DefaultIdentityID,
		Type:   "service",
		Method: method,
	}
}
