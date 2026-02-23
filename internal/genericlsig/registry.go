// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package genericlsig

import (
	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

// Register adds a Template to the unified lsigprovider registry.
// Called from init() functions in template packages.
// Key types are normalized to lowercase.
// If a template for the same key type is already registered, the call is ignored.
func Register(t Template) {
	lsigprovider.Register(t)
}

// Get retrieves a Template by its key type.
// Input is normalized to lowercase.
// Returns nil if not found or if the provider is not a Template.
func Get(keyType string) Template {
	p := lsigprovider.Get(keyType)
	if p == nil {
		return nil
	}
	// Only return if it's actually a Template (has TEAL generation)
	if t, ok := p.(Template); ok {
		return t
	}
	return nil
}

// GetOrError retrieves a Template by its key type.
// Input is normalized to lowercase.
// Returns an error if not found or if the provider is not a Template.
func GetOrError(keyType string) (Template, error) {
	p, err := lsigprovider.GetOrError(keyType)
	if err != nil {
		return nil, err
	}
	if t, ok := p.(Template); ok {
		return t, nil
	}
	return nil, lsigprovider.ErrNotTemplate
}

// GetAll returns all registered Templates, sorted by KeyType.
// Only returns providers that implement the Template interface.
func GetAll() []Template {
	var templates []Template
	for _, p := range lsigprovider.GetAll() {
		if t, ok := p.(Template); ok {
			templates = append(templates, t)
		}
	}
	return templates
}

// IsGenericLSigType checks if a key type is a registered generic LogicSig template.
// Input is normalized to lowercase.
func IsGenericLSigType(keyType string) bool {
	return Get(keyType) != nil
}

// Count returns the number of registered templates.
func Count() int {
	return len(GetAll())
}
