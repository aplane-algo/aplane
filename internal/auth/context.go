// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import "context"

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

const SystemProductAdminPrincipalID = "system:product-admin"

const productTokenCredentialID = "credential:product-token"

// NewProductIdentity returns the reserved product-admin principal for the
// given authentication method.
func NewProductIdentity(method string) *Identity {
	return &Identity{
		ID:     SystemProductAdminPrincipalID,
		Type:   "system",
		Method: method,
	}
}

// newProductTokenCredentialIdentity identifies a successfully validated token
// credential. Authorization boundaries map it to an application principal.
func newProductTokenCredentialIdentity(method string) *Identity {
	return &Identity{
		ID:     productTokenCredentialID,
		Type:   "credential",
		Method: method,
	}
}
