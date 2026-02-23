// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package signing provides cryptographic signature providers for key loading and signing.
//
// This package defines the Provider interface used for file-based key loading
// and signing operations. Both Ed25519 and Falcon implement this interface.
//
// For LogicSig-based post-quantum DSAs (Falcon, etc.), the Provider implementation
// acts as an adapter that delegates cryptographic operations to the corresponding
// LogicSigDSA implementation in internal/logicsigdsa.
//
// When adding a new post-quantum algorithm:
//  1. Implement LogicSigDSA in internal/logicsigdsa (core crypto operations)
//  2. Optionally add a Provider adapter here for file-based key loading
package signing

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/keys"
)

// KeyMaterial wraps provider-specific key data with type information
// This provides type safety and better debugging capabilities
type KeyMaterial struct {
	Type     string      // Key type identifier (e.g., "falcon1024-v1", "ed25519")
	Value    interface{} // The actual key data (provider-specific)
	Bytecode []byte      // LogicSig bytecode (nil for native ed25519)
}

// Provider defines the interface for cryptographic signature providers
// Each provider handles loading keys and signing messages for a specific algorithm
type Provider interface {
	// Family returns the algorithm family name (e.g., "falcon1024", "ed25519")
	// This is distinct from LogicSigDSA.KeyType() which returns versioned types like "falcon1024-v1"
	Family() string

	// LoadKeysFromData loads key pair from decrypted JSON data
	// Returns the key wrapped in KeyMaterial for type safety
	LoadKeysFromData(data []byte) (*KeyMaterial, error)

	// SignMessage signs a message with the provided key
	// The key must be a KeyMaterial with the correct type for this provider
	SignMessage(key *KeyMaterial, message []byte) ([]byte, error)

	// ZeroKey securely zeros the private key material
	ZeroKey(key *KeyMaterial)

	// DetectKeyType checks if the provided data (possibly encrypted) is this provider's key type
	// Returns true if this provider can handle the key
	DetectKeyType(keyData []byte, passphrase string) bool
}

// KeyLoader is a function that loads keys from data
// Used by the key session to abstract the loading process
type KeyLoader func(data []byte) (*KeyMaterial, error)

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

// DetectKeyTypeMatch is a helper for providers implementing DetectKeyType.
// It checks if unencrypted key data matches the expected key type.
// Returns false if passphrase is provided (encrypted data cannot be detected without decryption)
// or if the key type doesn't match.
func DetectKeyTypeMatch(keyData []byte, passphrase string, expectedKeyType string) bool {
	// If passphrase is provided, assume data is encrypted - we can't detect without decrypting
	if passphrase != "" {
		return false
	}

	// For unencrypted data, check the type field
	keyType, err := keys.DetectKeyTypeFromData(keyData)
	if err != nil {
		return false
	}
	return keyType == expectedKeyType
}
