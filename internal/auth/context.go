// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import "context"

import "github.com/aplane-algo/aplane/internal/productmode"

// DefaultIdentityID is the storage/request model default identity.
// Product-facing code should prefer CurrentProductIdentityID so the
// single-operator product assumption stays explicit.
const DefaultIdentityID = productmode.IdentityID

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

// NewDefaultIdentity returns the effective product identity for the given auth method.
func NewDefaultIdentity(method string) *Identity {
	return CurrentProductIdentity(method)
}
