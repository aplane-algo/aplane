// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
)

// Ed25519Provider implements signing.Provider for Ed25519 signatures
type Ed25519Provider struct{}

// RoutingFamily returns the algorithm family for Ed25519
func (p *Ed25519Provider) RoutingFamily() string {
	return "ed25519"
}

// LoadKeyMaterial loads Ed25519 key material from typed provider input.
func (p *Ed25519Provider) LoadKeyMaterial(key signing.ProviderKey) (*signing.KeyMaterial, error) {
	if key.Category != "ed25519" || key.Type != p.RoutingFamily() {
		return nil, fmt.Errorf("ed25519 provider cannot load category %q key type %q", key.Category, key.Type)
	}
	if len(key.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key length: expected %d bytes, got %d", ed25519.PrivateKeySize, len(key.PrivateKey))
	}

	account, err := algocrypto.AccountFromPrivateKey(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create account from private key: %w", err)
	}

	// Only Type and the crypto Value are the provider's to set; the keystore
	// stamps the storage envelope onto the returned KeyMaterial.
	return &signing.KeyMaterial{
		Type:  p.RoutingFamily(),
		Value: account,
	}, nil
}

// SignMessage signs a message using an Ed25519 key pair
func (p *Ed25519Provider) SignMessage(key *signing.KeyMaterial, message []byte) ([]byte, error) {
	// Validate key material
	if err := signing.ValidateKeyMaterial(key, p.RoutingFamily()); err != nil {
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

var registerProviderOnce sync.Once

// RegisterProvider registers the Ed25519 signing provider with the signing registry.
// This is idempotent and safe to call multiple times.
func RegisterProvider() {
	registerProviderOnce.Do(func() {
		signing.Register(&Ed25519Provider{})
	})
}
