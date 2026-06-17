// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	mnemonicreg "github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// LogicSigKeygenOps defines signer-side key generation for a versioned LogicSig key type.
type LogicSigKeygenOps interface {
	GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error)
}

type baseKeyTypeProvider interface {
	BaseKeyType() string
}

// LogicSigGenerator implements keygen.Generator for LogicSig-backed DSA
// families. It is family-neutral: keypair generation dispatches through the
// per-key-type ops map and mnemonic/seed derivation through the family's
// registered mnemonic handler.
type LogicSigGenerator struct {
	family          string
	keygenOpsByType map[string]LogicSigKeygenOps
}

// NewLogicSigGenerator returns a generator for the specified family.
func NewLogicSigGenerator(family string, keygenOpsByType map[string]LogicSigKeygenOps) *LogicSigGenerator {
	if family == "" {
		panic("LogicSigGenerator requires a family name")
	}
	if len(keygenOpsByType) == 0 {
		panic("LogicSigGenerator requires keygen ops")
	}
	opsCopy := make(map[string]LogicSigKeygenOps, len(keygenOpsByType))
	for keyType, ops := range keygenOpsByType {
		if ops == nil {
			panic("LogicSigGenerator got nil keygen ops for key type: " + keyType)
		}
		opsCopy[keyType] = ops
	}
	return &LogicSigGenerator{
		family:          family,
		keygenOpsByType: opsCopy,
	}
}

// Family returns the algorithm family this generator supports
func (g *LogicSigGenerator) Family() string {
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
func (g *LogicSigGenerator) generateKey(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, masterKey []byte, keyType string, params map[string]string, opts *keygenOpts) (*keygen.GenerationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	defer crypto.ZeroBytes(seed) // Zero seed after use

	dsa := logicsigdsa.Get(keyType)
	if dsa == nil {
		return nil, fmt.Errorf("%s not registered", keyType)
	}
	var provider lsigprovider.LSigProvider
	if p, ok := dsa.(lsigprovider.LSigProvider); ok {
		provider = p
		var err error
		params, err = lsigprovider.NormalizeCreationParams(params, provider.CreationParams())
		if err != nil {
			return nil, fmt.Errorf("%w: parameter normalization failed: %v", keygen.ErrInvalidParams, err)
		}
		if err := provider.ValidateCreationParams(params); err != nil {
			return nil, fmt.Errorf("%w: parameter validation failed: %v", keygen.ErrInvalidParams, err)
		}
	}
	baseKeyType := keyType
	if b, ok := dsa.(baseKeyTypeProvider); ok && b.BaseKeyType() != "" {
		baseKeyType = b.BaseKeyType()
	}
	// v1 signing-metadata key files always persist base_key_type, even when it
	// equals key_type, so load/sign paths have an explicit signing authority.

	keygenOps := g.keygenOpsByType[keyType]
	if keygenOps == nil {
		keygenOps = g.keygenOpsByType[g.Family()]
	}
	if keygenOps == nil {
		return nil, fmt.Errorf("no LogicSig keygen ops registered for %s", keyType)
	}

	// Generate key pair
	pub, priv, err := keygenOps.GenerateKeypair(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DSA key: %w", err)
	}
	defer crypto.ZeroBytes(priv)

	// Derive LogicSig, off-curve salt metadata, and address.
	lsigBytecode, address, saltCounter, err := deriveSaltedLogicSig(ctx, dsa, pub, params)
	if err != nil {
		return nil, fmt.Errorf("failed to derive LogicSig: %w", err)
	}

	// Capture TEAL source if DSA supports it
	var tealSource string
	if tg, ok := dsa.(logicsigdsa.TEALGenerator); ok {
		tealSource, _ = tg.GenerateTEAL(pub, params)
	}

	// Build key file structure
	keyPair := &keys.KeyPair{
		Category:               keys.CategoryDSALsig,
		KeyType:                keyType,
		PublicKeyHex:           hex.EncodeToString(pub),
		PrivateKeyHex:          hex.EncodeToString(priv),
		LsigBytecodeHex:        hex.EncodeToString(lsigBytecode),
		SaltCounter:            &saltCounter,
		Params:                 params,
		TEALSource:             tealSource,
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		BaseKeyType:            baseKeyType,
		TemplateFingerprint:    keys.TemplateFingerprintForKeyType(keyType),
	}
	if provider != nil {
		keyPair.SigningArgs = keys.StoreSigningArgs(provider.RuntimeArgs())
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
	keyFiles, err := keys.SaveKeyFile(paths, keyPair, identityID, address, masterKey)
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

func deriveSaltedLogicSig(ctx context.Context, dsa logicsigdsa.LogicSigDSA, publicKey []byte, params map[string]string) ([]byte, string, byte, error) {
	if salted, ok := dsa.(logicsigdsa.SaltedDeriver); ok {
		result, err := salted.DeriveLsigWithSalt(ctx, publicKey, params)
		if err != nil {
			return nil, "", 0, err
		}
		return result.Bytecode, result.Address.String(), result.Counter, nil
	}

	return nil, "", 0, fmt.Errorf("%s does not implement salted LogicSig derivation", dsa.KeyType())
}

// GenerateFromSeed generates a Falcon key from a deterministic seed.
// keyType must be a registered versioned type (e.g., "aplane.falcon1024.v1").
func (g *LogicSigGenerator) GenerateFromSeed(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, masterKey []byte, keyType string, params map[string]string) (*keygen.GenerationResult, error) {
	// Make a copy of seed since generateKey will zero it
	seedCopy := make([]byte, len(seed))
	copy(seedCopy, seed)

	return g.generateKey(ctx, paths, identityID, seedCopy, masterKey, keyType, params, nil)
}

// GenerateFromMnemonic generates a Falcon key from mnemonic words.
// keyType must be a registered versioned type (e.g., "aplane.falcon1024.v1").
// Seed and entropy derivation route through the family's registered mnemonic
// handler so families with a non-BIP-39 scheme derive correctly.
func (g *LogicSigGenerator) GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, identityID string, mnemonic string, masterKey []byte, keyType string, params map[string]string) (*keygen.GenerationResult, error) {
	handler, err := mnemonicreg.GetHandler(g.Family())
	if err != nil {
		return nil, err
	}

	// Convert mnemonic to seed
	words := strings.Fields(mnemonic)
	seed, err := handler.SeedFromMnemonic(words, "")
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}

	// Convert mnemonic back to entropy for storage (so it can be re-exported)
	entropy, err := handler.MnemonicToEntropy(words)
	if errors.Is(err, mnemonicreg.ErrEntropyUnsupported) {
		entropy = nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to derive entropy from mnemonic: %w", err)
	}
	defer crypto.ZeroBytes(entropy)

	derivation := ""
	if len(entropy) > 0 {
		derivation = "bip39-standard"
	}
	return g.generateKey(ctx, paths, identityID, seed, masterKey, keyType, params, &keygenOpts{
		entropy:    entropy,
		mnemonic:   mnemonic,
		derivation: derivation,
	})
}

// GenerateRandom generates a new random Falcon key.
// keyType must be a registered versioned type (e.g., "aplane.falcon1024.v1").
// Mnemonic, seed, and entropy come from the family's registered mnemonic
// handler so families with a non-BIP-39 scheme derive correctly.
func (g *LogicSigGenerator) GenerateRandom(ctx context.Context, paths storepaths.Paths, identityID string, masterKey []byte, keyType string, params map[string]string) (*keygen.GenerationResult, error) {
	handler, err := mnemonicreg.GetHandler(g.Family())
	if err != nil {
		return nil, err
	}

	mnemonic, seed, entropy, err := handler.GenerateMnemonic()
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(entropy)

	derivation := ""
	if len(entropy) > 0 {
		derivation = "bip39-standard"
	}
	return g.generateKey(ctx, paths, identityID, seed, masterKey, keyType, params, &keygenOpts{
		entropy:    entropy,
		mnemonic:   mnemonic,
		derivation: derivation,
	})
}
