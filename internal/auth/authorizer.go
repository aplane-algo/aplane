// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package auth

import (
	"context"
	"errors"
)

// Common authorization errors
var (
	// ErrUnauthorized indicates the identity is not authorized for the action
	ErrUnauthorized = errors.New("not authorized")

	// ErrForbidden indicates the action is forbidden for this identity
	ErrForbidden = errors.New("forbidden")
)

// Action represents an operation being performed
type Action string

// Common actions
const (
	ActionSign       Action = "sign"
	ActionListKeys   Action = "list_keys"
	ActionGetHealth  Action = "get_health"
	ActionManageKeys Action = "manage_keys"
)

// Resource represents the target of an action
type Resource struct {
	// Type is the resource type ("key", "transaction", "system")
	Type string

	// ID is the resource identifier (e.g., key address)
	ID string
}

// Authorizer determines if an identity is allowed to perform an action on a resource
type Authorizer interface {
	// Authorize checks if the identity can perform the action on the resource.
	// Returns nil if authorized, ErrUnauthorized or ErrForbidden otherwise.
	Authorize(ctx context.Context, identity *Identity, action Action, resource Resource) error
}

// AllowAllAuthorizer permits all actions for any authenticated identity.
// Use this for development/testing or when authorization is handled elsewhere.
type AllowAllAuthorizer struct{}

// NewAllowAllAuthorizer creates a new AllowAllAuthorizer
func NewAllowAllAuthorizer() *AllowAllAuthorizer {
	return &AllowAllAuthorizer{}
}

// Authorize always returns nil (allowed)
func (a *AllowAllAuthorizer) Authorize(ctx context.Context, identity *Identity, action Action, resource Resource) error {
	// All authenticated identities are authorized for all actions
	return nil
}

// Compile-time interface check
var _ Authorizer = (*AllowAllAuthorizer)(nil)
