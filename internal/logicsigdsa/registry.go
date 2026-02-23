// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package logicsigdsa

import (
	"github.com/aplane-algo/aplane/internal/lsigprovider"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// Register adds a LogicSigDSA implementation to the unified lsigprovider registry.
// The DSA must also implement lsigprovider.LSigProvider.
// This is typically called from init() functions in DSA packages.
// Key types are normalized to lowercase.
// If a DSA for the same key type is already registered, the call is ignored.
func Register(dsa LogicSigDSA) {
	// DSAs should implement LSigProvider
	if provider, ok := dsa.(lsigprovider.LSigProvider); ok {
		lsigprovider.Register(provider)
	}
}

// Get retrieves a LogicSigDSA by its key type (e.g., "falcon1024-v1").
// Input is normalized to lowercase.
// Returns nil if not found or if the provider is not a LogicSigDSA.
func Get(keyType string) LogicSigDSA {
	p := lsigprovider.Get(keyType)
	if p == nil {
		return nil
	}
	if dsa, ok := p.(LogicSigDSA); ok {
		return dsa
	}
	return nil
}

// GetAll returns all registered LogicSigDSA implementations.
// The returned slice is sorted by KeyType for deterministic ordering.
func GetAll() []LogicSigDSA {
	var dsas []LogicSigDSA
	for _, p := range lsigprovider.GetAll() {
		if dsa, ok := p.(LogicSigDSA); ok {
			dsas = append(dsas, dsa)
		}
	}
	return dsas
}

// GetKeyTypes returns a sorted list of all registered DSA key types.
func GetKeyTypes() []string {
	dsas := GetAll()
	keyTypes := make([]string, len(dsas))
	for i, dsa := range dsas {
		keyTypes[i] = dsa.KeyType()
	}
	return keyTypes
}

// IsRegistered checks if a key type is registered as a DSA.
// Input is normalized to lowercase.
func IsRegistered(keyType string) bool {
	return Get(keyType) != nil
}

// GetFamily returns the family name for a versioned key type.
// Delegates to lsigprovider.GetFamily.
func GetFamily(keyType string) string {
	return lsigprovider.GetFamily(keyType)
}

// IsLogicSigType checks if a key type uses LogicSig-based signatures.
// Only returns true for registered DSA types.
func IsLogicSigType(keyType string) bool {
	return IsRegistered(keyType)
}

// GetCryptoSignatureSize returns the cryptographic signature size for a key type.
// Returns 0 if the key type is not a LogicSig type or not registered.
// This is used for fee estimation (signature is appended to transactions).
func GetCryptoSignatureSize(keyType string) int {
	dsa := Get(keyType)
	if dsa == nil {
		return 0
	}
	return dsa.CryptoSignatureSize()
}

// ConfigureAlgodClient sets the algod client on all registered providers.
// Delegates to lsigprovider.ConfigureAlgodClient.
func ConfigureAlgodClient(client *algod.Client) {
	lsigprovider.ConfigureAlgodClient(client)
}
