// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/util"
)

var providers = util.NewStringRegistry[Provider]()

// Register adds a provider to the registry.
// Panics if a provider for the same family is already registered.
func Register(provider Provider) {
	family := provider.Family()
	if !providers.Set(family, provider) {
		panic("duplicate signing provider registration for family: " + family)
	}
}

// GetProvider retrieves a provider by key type.
// Versioned types like "falcon1024-v1" are normalized to their family type.
func GetProvider(keyType string) Provider {
	// Try direct lookup first
	if provider, ok := providers.Get(keyType); ok {
		return provider
	}

	// Try family name (e.g., "falcon1024-v1" -> "falcon1024")
	family := logicsigdsa.GetFamily(keyType)
	if family != keyType {
		provider, _ := providers.Get(family)
		return provider
	}

	return nil
}

// GetRegisteredFamilies returns a sorted list of all registered provider families.
// These are family names like "ed25519", "falcon1024", not versioned key types.
// This is useful for startup logging and debugging.
func GetRegisteredFamilies() []string {
	return providers.Keys()
}
