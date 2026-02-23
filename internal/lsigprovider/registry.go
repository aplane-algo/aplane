// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package lsigprovider

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/util"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// normalize lowercases a key type for consistent lookups.
func normalize(s string) string {
	return strings.ToLower(s)
}

var (
	providers    = util.NewStringRegistry[LSigProvider]()
	storedClient *algod.Client // Stored algod client for late-registered providers
)

// Register adds an LSigProvider to the unified registry.
// Key types are normalized to lowercase.
// If a provider for the same key type is already registered, the call is ignored.
// If an algod client was previously configured, it is automatically applied
// to providers that implement AlgodConfigurable.
func Register(p LSigProvider) {
	keyType := normalize(p.KeyType())
	if !providers.Set(keyType, p) {
		// Already registered - silently ignore (can happen during reload)
		return
	}

	// Apply stored algod client if available
	if storedClient != nil {
		if configurable, ok := p.(AlgodConfigurable); ok {
			configurable.SetAlgodClient(storedClient)
		}
	}
}

// Get retrieves an LSigProvider by its key type.
// Input is normalized to lowercase.
// Returns nil if not found.
func Get(keyType string) LSigProvider {
	p, _ := providers.Get(normalize(keyType))
	return p
}

// GetOrError retrieves an LSigProvider by its key type.
// Input is normalized to lowercase.
// Returns an error if not found.
func GetOrError(keyType string) (LSigProvider, error) {
	if p, ok := providers.Get(normalize(keyType)); ok {
		return p, nil
	}
	return nil, fmt.Errorf("no LSig provider found for: %s", keyType)
}

// GetAll returns all registered LSigProviders, sorted by KeyType.
func GetAll() []LSigProvider {
	return providers.Values()
}

// Has checks if a key type is registered.
// Input is normalized to lowercase.
func Has(keyType string) bool {
	return providers.Has(normalize(keyType))
}

// GetFamily returns the family name for a versioned key type.
// For example: "falcon1024-v1" -> "falcon1024"
// Input is normalized to lowercase.
// If the key type is not registered, returns the normalized input unchanged.
func GetFamily(keyType string) string {
	normalized := normalize(keyType)
	if p, ok := providers.Get(normalized); ok {
		return strings.ToLower(p.Family())
	}
	return normalized
}

// AlgodConfigurable is an optional interface for LSigProvider implementations
// that require an algod client for TEAL compilation (e.g., ComposedDSA).
type AlgodConfigurable interface {
	SetAlgodClient(client *algod.Client)
}

// ConfigureAlgodClient sets the algod client on all registered providers that
// implement AlgodConfigurable. This enables runtime TEAL compilation for
// composed providers during key import and derivation.
//
// The client is stored so that providers registered later (e.g., from keystore
// templates loaded after unlock) are automatically configured.
//
// Should be called during server startup after initial providers are registered.
func ConfigureAlgodClient(client *algod.Client) {
	storedClient = client
	for _, p := range GetAll() {
		if configurable, ok := p.(AlgodConfigurable); ok {
			configurable.SetAlgodClient(client)
		}
	}
}
