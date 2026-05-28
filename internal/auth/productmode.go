// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import (
	"errors"
	"fmt"
)

// ProductModeSingleOperator describes the currently supported operator model.
const ProductModeSingleOperator = "single-operator"

// ErrUnsupportedProductIdentity indicates a caller requested an identity outside
// the currently supported single-operator product mode.
var ErrUnsupportedProductIdentity = errors.New("unsupported identity")

// CurrentProductIdentityID returns the effective identity for the current product mode.
// The storage and request model remains identity-aware even though the supported product
// deployment is still effectively single-operator today.
func CurrentProductIdentityID() string {
	return DefaultIdentityID
}

// IsCurrentProductIdentity reports whether the supplied identity matches the
// currently supported product identity.
func IsCurrentProductIdentity(identityID string) bool {
	return identityID == CurrentProductIdentityID()
}

// RequireCurrentProductIdentity validates that the supplied identity matches the
// currently supported product identity.
func RequireCurrentProductIdentity(identityID string) error {
	if IsCurrentProductIdentity(identityID) {
		return nil
	}
	return fmt.Errorf("%w: %s (only %q is currently supported)", ErrUnsupportedProductIdentity, identityID, CurrentProductIdentityID())
}

// CurrentProductIdentity returns the effective service identity for the current product mode.
func CurrentProductIdentity(method string) *Identity {
	return &Identity{
		ID:     CurrentProductIdentityID(),
		Type:   "service",
		Method: method,
	}
}
