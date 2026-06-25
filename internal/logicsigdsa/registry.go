// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package logicsigdsa

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/lsigprovider"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// Register adds a LogicSigDSA implementation to the unified lsigprovider registry.
// The DSA must also implement lsigprovider.LSigProvider.
// This is typically called from init() functions in DSA packages.
// Key types are normalized to lowercase.
// Panics if the DSA does not satisfy the unified LSigProvider contract.
func Register(dsa LogicSigDSA) {
	// DSAs should implement LSigProvider
	if provider, ok := dsa.(lsigprovider.LSigProvider); ok {
		lsigprovider.Register(provider)
		return
	}

	panic(fmt.Sprintf("LogicSigDSA %T does not implement lsigprovider.LSigProvider", dsa))
}

// RegisterIfAbsent adds a LogicSigDSA unless its key type is already present.
// It returns true when newly registered and false when the key type was
// already registered.
func RegisterIfAbsent(dsa LogicSigDSA) bool {
	if provider, ok := dsa.(lsigprovider.LSigProvider); ok {
		return lsigprovider.RegisterIfAbsent(provider)
	}

	panic(fmt.Sprintf("LogicSigDSA %T does not implement lsigprovider.LSigProvider", dsa))
}

// Get retrieves a LogicSigDSA by its key type (e.g., "aplane.falcon1024.v1").
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

// RoutingFamily returns a key type's provider-declared ROUTING family — the
// family the keygen/signing/mnemonic/metadata registries are indexed by (the
// key type's own family for a self-handling DSA, or the base's family for a
// composed template that delegates). It is not the key type's own display
// label. Delegates to lsigprovider.RoutingFamily.
func RoutingFamily(keyType string) string {
	return lsigprovider.RoutingFamily(keyType)
}

// ResolveByKeyType resolves a value for keyType from a registry keyed by routing
// family, using the standard two-step lookup the family-keyed registries share:
// an exact key-type match first (native and per-key-type registrations), then
// the key type's RoutingFamily. get reads the caller's registry (it runs under
// whatever lock the caller holds). It returns the zero value and false when
// neither matches.
//
// Note: keygen deliberately does NOT use this — it must reject sentry key types
// between the exact and family steps, so its lookup is spelled out inline.
func ResolveByKeyType[T any](keyType string, get func(string) (T, bool)) (T, bool) {
	if v, ok := get(keyType); ok {
		return v, true
	}
	if family := RoutingFamily(keyType); family != keyType {
		if v, ok := get(family); ok {
			return v, true
		}
	}
	var zero T
	return zero, false
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
