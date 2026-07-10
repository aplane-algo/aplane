// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/xregistry"
)

var providers = xregistry.NewStringRegistry[Provider]()

// Register adds a provider to the registry.
// Panics if a provider for the same family is already registered.
// This is called at init time only — a duplicate here is a programming error.
func Register(provider Provider) {
	family := provider.RoutingFamily()
	if !providers.Set(family, provider) {
		panic("duplicate signing provider registration for family: " + family)
	}
}

// GetProvider retrieves a provider by key type, resolving via the key type's
// routing family (e.g. "aplane.falcon1024.v1" / a falcon-based template ->
// "aplane.falcon1024"). Returns nil if none is registered.
func GetProvider(keyType string) Provider {
	provider, _ := logicsigdsa.ResolveByKeyType(keyType, providers.Get)
	return provider
}

// GetProviderForKey resolves the signing provider for a stored key: the
// versioned key type first, then the durable base key type recorded in the
// key file. This is the single owner of the route-by-base-key-type fallback.
// Returns nil if neither resolves.
func GetProviderForKey(keyType, baseKeyType string) Provider {
	if provider := GetProvider(keyType); provider != nil {
		return provider
	}
	if baseKeyType != "" {
		return GetProvider(baseKeyType)
	}
	return nil
}

// GetRegisteredFamilies returns a sorted list of all registered provider families.
// These are family names like "ed25519", "falcon1024", not versioned key types.
// This is useful for startup logging and debugging.
func GetRegisteredFamilies() []string {
	return providers.Keys()
}
