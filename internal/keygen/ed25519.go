// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keygen

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/auth"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Ed25519Generator implements Generator for Ed25519 keys
type Ed25519Generator struct{}

// Family returns the algorithm family this generator supports
func (g *Ed25519Generator) Family() string {
	return "ed25519"
}

// GenerateFromSeed generates an Ed25519 key from a deterministic seed.
// keyType must be "ed25519".
func (g *Ed25519Generator) GenerateFromSeed(seed []byte, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
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
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Convert to Algorand address
	var algoPubKey types.Address
	copy(algoPubKey[:], publicKey[:32])
	address := algoPubKey.String()

	// Save key files
	keyFiles, err := saveEd25519Keys(publicKey, privateKey, address, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to save keys: %w", err)
	}

	return &GenerationResult{
		Address:      address,
		KeyType:      "ed25519",
		PublicKeyHex: fmt.Sprintf("%x", publicKey),
		Mnemonic:     "",
		KeyFiles:     keyFiles,
	}, nil
}

// GenerateFromMnemonic generates an Ed25519 key from Algorand mnemonic words.
// keyType must be "ed25519".
func (g *Ed25519Generator) GenerateFromMnemonic(mnemonicStr string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = params
	if keyType != "ed25519" {
		return nil, fmt.Errorf("ed25519 generator only supports keyType \"ed25519\", got %q", keyType)
	}

	// Derive private key from mnemonic (Algorand format, 25 words)
	privateKey, err := mnemonic.ToPrivateKey(mnemonicStr)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key from mnemonic: %w", err)
	}

	// In Algorand SDK, the private key is the seed
	seed := privateKey[:32]

	// Generate key from seed
	result, err := g.GenerateFromSeed(seed, masterKey, keyType, nil)
	if err != nil {
		return nil, err
	}

	// Add the mnemonic to the result
	result.Mnemonic = mnemonicStr
	return result, nil
}

// GenerateRandom generates a new random Ed25519 key.
// keyType must be "ed25519".
func (g *Ed25519Generator) GenerateRandom(masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = params
	if keyType != "ed25519" {
		return nil, fmt.Errorf("ed25519 generator only supports keyType \"ed25519\", got %q", keyType)
	}

	// Generate Ed25519 account using Algorand SDK
	account := algocrypto.GenerateAccount()

	// Convert private key to 25-word mnemonic
	mnemonicStr, err := mnemonic.FromPrivateKey(account.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// Save key files
	keyFiles, err := saveEd25519Keys(account.PublicKey, account.PrivateKey, account.Address.String(), masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to save keys: %w", err)
	}

	return &GenerationResult{
		Address:      account.Address.String(),
		KeyType:      "ed25519",
		PublicKeyHex: fmt.Sprintf("%x", account.PublicKey),
		Mnemonic:     mnemonicStr,
		KeyFiles:     keyFiles,
	}, nil
}

// saveEd25519Keys saves Ed25519 key files to disk using the shared SaveKeyFile helper
func saveEd25519Keys(publicKey []byte, privateKey []byte, address string, masterKey []byte) (*utilkeys.ImportKeyResult, error) {
	keyPair := &utilkeys.KeyPair{
		Category:      utilkeys.CategoryEd25519,
		KeyType:       "ed25519",
		PublicKeyHex:  fmt.Sprintf("%x", publicKey),
		PrivateKeyHex: fmt.Sprintf("%x", privateKey),
	}
	return utilkeys.SaveKeyFile(keyPair, auth.DefaultIdentityID, address, masterKey)
}

var registerEd25519GeneratorOnce sync.Once

// RegisterEd25519Generator registers the Ed25519 key generator with the keygen registry.
// This is idempotent and safe to call multiple times.
func RegisterEd25519Generator() {
	registerEd25519GeneratorOnce.Do(func() {
		Register(&Ed25519Generator{})
	})
}
