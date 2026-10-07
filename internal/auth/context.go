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

// ClientPrincipalPrefix prefixes the principal ID of an enrolled client. The
// rest of the ID is the SHA256 fingerprint of the client's SSH key.
const ClientPrincipalPrefix = "client:"

// Roles select an identity's permissions. The role is assigned by the
// trusted authentication path, never read from a request.
const (
	// RoleClient is an enrolled client key: it may sign and read, and it
	// never administers.
	RoleClient = "client"
)

// MethodSSHKey is the authentication method of a client identified by its
// enrolled SSH key on a tunneled connection.
const MethodSSHKey = "ssh-key"

// NewProductIdentity returns the reserved product-admin principal for the
// given authentication method.
func NewProductIdentity(method string) *Identity {
	return &Identity{
		ID:     SystemProductAdminPrincipalID,
		Type:   "system",
		Method: method,
	}
}

// NewClientIdentity returns the principal of an enrolled client key. The
// fingerprint identifies the credential; label is display information.
func NewClientIdentity(fingerprint, label string) *Identity {
	return &Identity{
		ID:             ClientPrincipalPrefix + fingerprint,
		Type:           "client",
		Method:         MethodSSHKey,
		Role:           RoleClient,
		KeyFingerprint: fingerprint,
		Label:          label,
	}
}

// ConnIdentity is what the transport verified about a connection before any
// request was read: the enrolled key that authenticated it. It is attached
// to the connection's context by the HTTP server and is the only source of
// client identity; nothing in a request can supply or override it.
type ConnIdentity struct {
	KeyFingerprint string
}

type connIdentityKey struct{}

// ContextWithConnIdentity attaches a connection identity.
func ContextWithConnIdentity(ctx context.Context, id ConnIdentity) context.Context {
	return context.WithValue(ctx, connIdentityKey{}, id)
}

// ConnIdentityFromContext returns the connection identity, if the connection
// was authenticated by the transport.
func ConnIdentityFromContext(ctx context.Context) (ConnIdentity, bool) {
	id, ok := ctx.Value(connIdentityKey{}).(ConnIdentity)
	return id, ok && id.KeyFingerprint != ""
}
