// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"

	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/storepaths"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
)

// Ed25519Generator implements Generator for Ed25519 keys
type Ed25519Generator struct{}

// RoutingFamily returns the algorithm family this generator supports
func (g *Ed25519Generator) RoutingFamily() string {
	return "ed25519"
}

// GenerateFromSeed generates an Ed25519 key from a deterministic seed.
// keyType must be "ed25519".
func (g *Ed25519Generator) GenerateFromSeed(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, kr *securecrypto.Keyring, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != "ed25519" {
		return nil, fmt.Errorf("ed25519 generator only supports keyType \"ed25519\", got %q", keyType)
	}

	// For Ed25519, the seed is the private key (32 bytes)
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size for ed25519: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}

	// Generate key pair from seed
	privateKey := ed25519.NewKeyFromSeed(seed)
	defer securecrypto.ZeroBytes(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Save key files
	keyFiles, err := saveEd25519Keys(paths, identityID, publicKey, privateKey, kr)
	if err != nil {
		return nil, fmt.Errorf("failed to save keys: %w", err)
	}

	return &GenerationResult{
		Address:      keyFiles.Address,
		KeyType:      "ed25519",
		PublicKeyHex: fmt.Sprintf("%x", publicKey),
		Mnemonic:     "",
		KeyFiles:     keyFiles,
	}, nil
}

// GenerateFromMnemonic generates an Ed25519 key from Algorand mnemonic words.
// keyType must be "ed25519".
func (g *Ed25519Generator) GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, identityID string, mnemonicStr string, kr *securecrypto.Keyring, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = params
	if keyType != "ed25519" {
		return nil, fmt.Errorf("ed25519 generator only supports keyType \"ed25519\", got %q", keyType)
	}

	// Derive private key from mnemonic (Algorand format, 25 words)
	privateKey, err := mnemonic.ToPrivateKey(mnemonicStr)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key from mnemonic: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	// In Algorand SDK, the private key is the seed
	seed := append([]byte(nil), privateKey[:32]...)
	defer securecrypto.ZeroBytes(seed)

	// Generate key from seed
	result, err := g.GenerateFromSeed(ctx, paths, identityID, seed, kr, keyType, nil)
	if err != nil {
		return nil, err
	}

	// Add the mnemonic to the result
	result.Mnemonic = mnemonicStr
	return result, nil
}

// GenerateRandom generates a new random Ed25519 key.
// keyType must be "ed25519".
func (g *Ed25519Generator) GenerateRandom(ctx context.Context, paths storepaths.Paths, identityID string, kr *securecrypto.Keyring, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != "ed25519" {
		return nil, fmt.Errorf("ed25519 generator only supports keyType \"ed25519\", got %q", keyType)
	}

	// Generate Ed25519 account using Algorand SDK
	account := algocrypto.GenerateAccount()
	defer securecrypto.ZeroBytes(account.PrivateKey)

	// Convert private key to 25-word mnemonic
	mnemonicStr, err := mnemonic.FromPrivateKey(account.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// Save key files
	keyFiles, err := saveEd25519Keys(paths, identityID, account.PublicKey, account.PrivateKey, kr)
	if err != nil {
		return nil, fmt.Errorf("failed to save keys: %w", err)
	}

	return &GenerationResult{
		Address:      keyFiles.Address,
		KeyType:      "ed25519",
		PublicKeyHex: fmt.Sprintf("%x", account.PublicKey),
		Mnemonic:     mnemonicStr,
		KeyFiles:     keyFiles,
	}, nil
}

// saveEd25519Keys saves an Ed25519 key under its payload-derived address.
func saveEd25519Keys(paths storepaths.Paths, identityID string, publicKey []byte, privateKey []byte, kr *securecrypto.Keyring) (*keys.ImportKeyResult, error) {
	payload := keys.NewEd25519Payload(publicKey, privateKey)
	defer payload.ZeroSecrets()
	return keys.SavePayload(paths, identityID, payload, kr)
}

var registerEd25519GeneratorOnce sync.Once

// RegisterEd25519Generator registers the Ed25519 key generator with the keygen registry.
// This is idempotent and safe to call multiple times.
func RegisterEd25519Generator() {
	registerEd25519GeneratorOnce.Do(func() {
		Register(&Ed25519Generator{})
	})
}
