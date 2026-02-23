// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package falcon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/signing"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// FalconProvider implements signing.Provider for Falcon-1024 signatures.
// The family can be overridden to allow alias registrations (e.g., hybrid families).
type FalconProvider struct {
	family string
}

// NewFalconProvider returns a Falcon signing provider for the specified family.
func NewFalconProvider(family string) *FalconProvider {
	return &FalconProvider{family: family}
}

// Family returns the algorithm family for Falcon-1024
func (p *FalconProvider) Family() string {
	if p.family == "" {
		return "falcon1024"
	}
	return p.family
}

// FalconKeyMaterial holds the raw key bytes for signing
type FalconKeyMaterial struct {
	PrivateKey []byte
}

// LoadKeysFromData loads Falcon key pair from decrypted JSON data
// SECURITY: This function zeroes all intermediate key material after use
func (p *FalconProvider) LoadKeysFromData(data []byte) (*signing.KeyMaterial, error) {
	var keyPair utilkeys.KeyPair

	if err := json.Unmarshal(data, &keyPair); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keys: %w", err)
	}

	// Validate key type belongs to this family
	if logicsigdsa.GetFamily(keyPair.KeyType) != p.Family() {
		return nil, fmt.Errorf("key type %q does not belong to family %q", keyPair.KeyType, p.Family())
	}

	privBytes, err := hex.DecodeString(keyPair.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex: %w", err)
	}

	// Zero the hex strings from the keys struct
	defer func() {
		crypto.ZeroBytes([]byte(keyPair.PrivateKeyHex))
		keyPair.PrivateKeyHex = ""
	}()

	// Store raw bytes with the key's actual versioned type
	return &signing.KeyMaterial{
		Type: keyPair.KeyType, // Use the exact versioned type from the key file
		Value: &FalconKeyMaterial{
			PrivateKey: privBytes,
		},
	}, nil
}

// SignMessage signs a message using a Falcon key pair
func (p *FalconProvider) SignMessage(key *signing.KeyMaterial, message []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("key material is nil")
	}

	// Validate key type belongs to this family
	if logicsigdsa.GetFamily(key.Type) != p.Family() {
		return nil, fmt.Errorf("key type %q does not belong to family %q", key.Type, p.Family())
	}

	km, ok := key.Value.(*FalconKeyMaterial)
	if !ok {
		return nil, fmt.Errorf("invalid key value for Falcon provider: expected *FalconKeyMaterial")
	}

	// Use the key's actual versioned type to look up the DSA
	dsa := logicsigdsa.Get(key.Type)
	if dsa == nil {
		return nil, fmt.Errorf("no LogicSigDSA registered for %s", key.Type)
	}

	sig, err := dsa.Sign(km.PrivateKey, message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return sig, nil
}

// ZeroKey securely zeros the Falcon private key material
func (p *FalconProvider) ZeroKey(key *signing.KeyMaterial) {
	if key == nil {
		return
	}

	if km, ok := key.Value.(*FalconKeyMaterial); ok {
		crypto.ZeroBytes(km.PrivateKey)
		km.PrivateKey = nil
	}

	// Clear the wrapper
	key.Type = ""
	key.Value = nil
}

// DetectKeyType checks if the provided data contains Falcon keys
func (p *FalconProvider) DetectKeyType(keyData []byte, passphrase string) bool {
	// If passphrase is provided, assume data is encrypted - we can't detect without decrypting
	if passphrase != "" {
		return false
	}

	// For unencrypted data, check the type field
	keyType, err := keys.DetectKeyTypeFromData(keyData)
	if err != nil {
		return false
	}

	// Check if the key type belongs to the falcon1024 family
	return logicsigdsa.GetFamily(keyType) == p.Family()
}

var registerProviderOnce sync.Once

// RegisterProvider registers the Falcon signing provider with the signing registry.
// This is idempotent and safe to call multiple times.
func RegisterProvider() {
	registerProviderOnce.Do(func() {
		signing.Register(NewFalconProvider("falcon1024"))
	})
}
