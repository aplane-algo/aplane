// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
)

// Ed25519Keys represents an Ed25519 key pair stored on disk
type Ed25519Keys struct {
	Type          string `json:"type"`
	PublicKeyHex  string `json:"public_key"`
	PrivateKeyHex string `json:"private_key"`
}

// Ed25519Provider implements signing.Provider for Ed25519 signatures
type Ed25519Provider struct{}

// Family returns the algorithm family for Ed25519
func (p *Ed25519Provider) Family() string {
	return "ed25519"
}

// LoadKeysFromData loads Ed25519 key pair from decrypted JSON data
// SECURITY: This function zeroes all intermediate key material after use
func (p *Ed25519Provider) LoadKeysFromData(data []byte) (*signing.KeyMaterial, error) {
	var keypair Ed25519Keys

	if err := json.Unmarshal(data, &keypair); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keys: %w", err)
	}

	// Decode private key hex
	privBytes, err := hex.DecodeString(keypair.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex: %w", err)
	}
	// Zero the hex-decoded private key bytes after copying
	defer crypto.ZeroBytes(privBytes)

	// Zero the hex strings from the keys struct
	defer func() {
		crypto.ZeroBytes([]byte(keypair.PrivateKeyHex))
		keypair.PrivateKeyHex = ""
	}()

	// Convert to crypto.Account
	// Ed25519 private keys in Algorand SDK are 64 bytes (32-byte seed + 32-byte public key)
	if len(privBytes) != 64 {
		return nil, fmt.Errorf("invalid Ed25519 private key length: expected 64 bytes, got %d", len(privBytes))
	}

	account, err := algocrypto.AccountFromPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create account from private key: %w", err)
	}

	return &signing.KeyMaterial{
		Type:  p.Family(),
		Value: account,
	}, nil
}

// SignMessage signs a message using an Ed25519 key pair
func (p *Ed25519Provider) SignMessage(key *signing.KeyMaterial, message []byte) ([]byte, error) {
	// Validate key material
	if err := signing.ValidateKeyMaterial(key, p.Family()); err != nil {
		return nil, err
	}

	account, ok := key.Value.(algocrypto.Account)
	if !ok {
		return nil, fmt.Errorf("invalid key value for Ed25519 provider: expected crypto.Account")
	}

	// Sign using standard Ed25519 signing
	// account.PrivateKey is 64 bytes (32-byte seed + 32-byte public key)
	signature := ed25519.Sign(account.PrivateKey, message)
	return signature, nil
}

// ZeroKey securely zeros the Ed25519 private key material
func (p *Ed25519Provider) ZeroKey(key *signing.KeyMaterial) {
	if key == nil {
		return
	}

	if account, ok := key.Value.(algocrypto.Account); ok {
		crypto.ZeroBytes(account.PrivateKey[:])
		// Also zero public key for completeness
		crypto.ZeroBytes(account.PublicKey[:])
	}

	// Clear the wrapper
	key.Type = ""
	key.Value = nil
}

// DetectKeyType checks if the provided data contains Ed25519 keys
func (p *Ed25519Provider) DetectKeyType(keyData []byte, passphrase string) bool {
	return signing.DetectKeyTypeMatch(keyData, passphrase, "ed25519")
}

var registerProviderOnce sync.Once

// RegisterProvider registers the Ed25519 signing provider with the signing registry.
// This is idempotent and safe to call multiple times.
func RegisterProvider() {
	registerProviderOnce.Do(func() {
		signing.Register(&Ed25519Provider{})
	})
}
