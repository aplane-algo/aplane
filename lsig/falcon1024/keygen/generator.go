// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keygen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"

	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// FalconGenerator implements Generator for Falcon-1024 keys.
// The family can be overridden to allow alias registrations (e.g., hybrid families).
type FalconGenerator struct {
	family string
}

// NewFalconGenerator returns a Falcon generator for the specified family.
func NewFalconGenerator(family string) *FalconGenerator {
	return &FalconGenerator{family: family}
}

// Family returns the algorithm family this generator supports
func (g *FalconGenerator) Family() string {
	if g.family == "" {
		return "falcon1024"
	}
	return g.family
}

// keygenOpts holds optional parameters for key generation.
// These control whether entropy/mnemonic are stored and returned.
type keygenOpts struct {
	entropy    []byte // If set, stored in key file for mnemonic re-export
	mnemonic   string // If set, returned in result
	derivation string // If set (e.g., "bip39-standard"), stored in key file
}

// generateKey is the internal helper that handles the common keygen logic:
// keypair generation, LSig derivation, key file saving, and result building.
// All sensitive data (seed, priv) is zeroed by this function.
func (g *FalconGenerator) generateKey(seed []byte, masterKey []byte, keyType string, params map[string]string, opts *keygenOpts) (*keygen.GenerationResult, error) {
	defer crypto.ZeroBytes(seed) // Zero seed after use

	dsa := logicsigdsa.Get(keyType)
	if dsa == nil {
		return nil, fmt.Errorf("%s not registered", keyType)
	}

	// Generate key pair
	pub, priv, err := dsa.GenerateKeypair(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Falcon key: %w", err)
	}
	defer crypto.ZeroBytes(priv)

	// Derive LogicSig and address
	lsigBytecode, address, err := dsa.DeriveLsig(pub, params)
	if err != nil {
		return nil, fmt.Errorf("failed to derive LogicSig: %w", err)
	}

	// Capture TEAL source if DSA supports it
	var tealSource string
	if tg, ok := dsa.(logicsigdsa.TEALGenerator); ok {
		tealSource, _ = tg.GenerateTEAL(pub, params)
	}

	// Build key file structure
	keyPair := &utilkeys.KeyPair{
		Category:        utilkeys.CategoryDSALsig,
		KeyType:         keyType,
		PublicKeyHex:    hex.EncodeToString(pub),
		PrivateKeyHex:   hex.EncodeToString(priv),
		LsigBytecodeHex: hex.EncodeToString(lsigBytecode),
		Params:          params,
		TEALSource:      tealSource,
	}

	// Add optional fields for mnemonic support
	if opts != nil {
		if len(opts.entropy) > 0 {
			keyPair.EntropyHex = hex.EncodeToString(opts.entropy)
		}
		if opts.derivation != "" {
			keyPair.Derivation = opts.derivation
		}
	}

	// Save key file
	keyFiles, err := utilkeys.SaveKeyFile(keyPair, auth.DefaultIdentityID, address, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to save keys: %w", err)
	}

	// Build result
	result := &keygen.GenerationResult{
		Address:      address,
		KeyType:      keyType,
		PublicKeyHex: hex.EncodeToString(pub),
		KeyFiles:     keyFiles,
	}
	if opts != nil {
		result.Mnemonic = opts.mnemonic
	}

	return result, nil
}

// GenerateFromSeed generates a Falcon key from a deterministic seed.
// keyType must be a registered versioned type (e.g., "falcon1024-v1").
func (g *FalconGenerator) GenerateFromSeed(seed []byte, masterKey []byte, keyType string, params map[string]string) (*keygen.GenerationResult, error) {
	// Make a copy of seed since generateKey will zero it
	seedCopy := make([]byte, len(seed))
	copy(seedCopy, seed)

	return g.generateKey(seedCopy, masterKey, keyType, params, nil)
}

// GenerateFromMnemonic generates a Falcon key from mnemonic words.
// keyType must be a registered versioned type (e.g., "falcon1024-v1").
func (g *FalconGenerator) GenerateFromMnemonic(mnemonic string, masterKey []byte, keyType string, params map[string]string) (*keygen.GenerationResult, error) {
	// Convert mnemonic to seed
	words := strings.Fields(mnemonic)
	seedArray, err := falconmnemonic.SeedFromMnemonic(words, "")
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}

	// Convert mnemonic back to entropy for storage (so it can be re-exported)
	entropy, err := falconmnemonic.MnemonicToEntropy(words)
	if err != nil {
		return nil, fmt.Errorf("failed to derive entropy from mnemonic: %w", err)
	}
	defer crypto.ZeroBytes(entropy)

	return g.generateKey(seedArray[:], masterKey, keyType, params, &keygenOpts{
		entropy:    entropy,
		mnemonic:   mnemonic,
		derivation: "bip39-standard",
	})
}

// GenerateRandom generates a new random Falcon key.
// keyType must be a registered versioned type (e.g., "falcon1024-v1").
func (g *FalconGenerator) GenerateRandom(masterKey []byte, keyType string, params map[string]string) (*keygen.GenerationResult, error) {
	// Generate 256 bits of entropy (24 words)
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}
	defer crypto.ZeroBytes(entropy)

	// Convert entropy to mnemonic
	words, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic from entropy: %w", err)
	}
	mnemonic := strings.Join(words, " ")

	// Derive seed from mnemonic
	seedArray, err := falconmnemonic.SeedFromMnemonic(words, "")
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}

	return g.generateKey(seedArray[:], masterKey, keyType, params, &keygenOpts{
		entropy:    entropy,
		mnemonic:   mnemonic,
		derivation: "bip39-standard",
	})
}

var registerGeneratorOnce sync.Once

// RegisterGenerator registers the Falcon key generator with the keygen registry.
// This is idempotent and safe to call multiple times.
func RegisterGenerator() {
	registerGeneratorOnce.Do(func() {
		keygen.Register(NewFalconGenerator("falcon1024"))
	})
}
