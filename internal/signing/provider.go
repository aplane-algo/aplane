// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signing provides cryptographic signature providers for key loading and signing.
//
// This package defines the Provider interface used for file-based key loading
// and signing operations. Both Ed25519 and Falcon implement this interface.
//
// For LogicSig-based post-quantum DSAs (Falcon, etc.), the Provider implementation
// acts as an adapter around explicit signer-side operation handles. It does not
// reach through the client-visible LogicSigDSA registry for private-key signing.
//
// When adding a new post-quantum algorithm:
//  1. Implement LogicSigDSA metadata/derivation in internal/logicsigdsa
//  2. Implement signer-side operation handles for private-key signing
//  3. Optionally add a Provider adapter here for file-based key loading
package signing

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

// KeyMaterial wraps provider-specific key data with type information
// This provides type safety and better debugging capabilities
type KeyMaterial struct {
	Type                   string                       // Key type identifier (e.g., "aplane.falcon1024.v1", "ed25519")
	Value                  interface{}                  // The actual key data (provider-specific)
	PublicKey              []byte                       // Public key bytes, when available from the key file
	Bytecode               []byte                       // LogicSig bytecode (nil for native ed25519)
	Category               string                       // Key category recorded in the key file, if any
	PQScheme               string                       // Native PQ scheme tag, when Category is native_pq
	PQAddressSalt          *byte                        // Canonical native PQ address salt
	BaseKeyType            string                       // Base DSA key type used for signer ops, if different from Type
	Parameters             map[string]string            // Creation parameters recorded in the key file, if any
	SigningArgs            []lsigprovider.RuntimeArgDef // Durable signing-time LogicSig arg contract
	BoundedAuthorization   *boundedmeta.Metadata        // Durable bounded signing and routing contract
	SigningMetadataVersion int                          // Version of durable key-file signing metadata
}

// WitnessKeyMaterial holds raw signer-custodied witness material. Witness keys
// are not transaction-signing provider keys and this hot custody class may be
// used only by the sentry component-signing flow.
type WitnessKeyMaterial struct {
	WitnessKeyID string
	PublicKey    []byte
	PrivateKey   []byte
}

// ProviderKey is the minimal typed key input passed to signing providers after
// the storage payload has been parsed and validated by internal/keys: the
// routing identity plus the private key material. Storage metadata (category,
// public key, signing args, ...) is stamped onto the returned KeyMaterial by
// the keystore, not routed through providers.
//
// OWNERSHIP: PrivateKey aliases a caller-owned buffer that is zeroed when the
// key-load call returns. Providers must deep-copy any material they retain
// beyond LoadKeyMaterial; retaining the slice itself yields a zeroed key.
type ProviderKey struct {
	Type        string
	BaseKeyType string
	PrivateKey  []byte
}

// Provider defines the interface for cryptographic signature providers
// Each provider handles loading keys and signing messages for a specific algorithm
type Provider interface {
	// RoutingFamily returns the algorithm family name (e.g., "falcon1024", "ed25519")
	// This is distinct from LogicSigDSA.KeyType() which returns versioned types like "aplane.falcon1024.v1"
	RoutingFamily() string

	// LoadKeyMaterial loads key material from typed, decoded provider input.
	// The ProviderKey byte slices are valid only for the duration of the call
	// (the caller zeroes them on return); implementations must copy anything
	// they keep in the returned KeyMaterial.
	// Returns the key wrapped in KeyMaterial for type safety
	LoadKeyMaterial(key ProviderKey) (*KeyMaterial, error)

	// SignMessage signs a message with the provided key
	// The key must be a KeyMaterial with the correct type for this provider
	SignMessage(key *KeyMaterial, message []byte) ([]byte, error)

	// ZeroKey securely zeros the private key material
	ZeroKey(key *KeyMaterial)
}

// ValidateKeyMaterial checks if KeyMaterial has the expected type
// Returns an error if the type doesn't match
func ValidateKeyMaterial(key *KeyMaterial, expectedType string) error {
	if key == nil {
		return fmt.Errorf("key material is nil")
	}
	if key.Type != expectedType {
		return fmt.Errorf("key type mismatch: expected %s, got %s", expectedType, key.Type)
	}
	if key.Value == nil {
		return fmt.Errorf("key value is nil for type %s", expectedType)
	}
	return nil
}
