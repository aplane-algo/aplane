// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keygen creates Ed25519 witness keys: a cosigner's component keys.
package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"

	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	internalkeygen "github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	sigverify "github.com/aplane-algo/aplane/internal/sigconstruction/verify"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

// WitnessEd25519Generator creates raw Ed25519 witness keys. They are not
// Algorand spending accounts, although an Ed25519 public key is also an
// address, and are registered only under their exact witness key type.
type WitnessEd25519Generator struct{}

func (g *WitnessEd25519Generator) RoutingFamily() string {
	return witness.Ed25519V1
}

func (g *WitnessEd25519Generator) GenerateFromSeed(_ context.Context, paths storepaths.Paths, seed []byte, kr *securecrypto.Keyring, keyType string, _ map[string]string) (*internalkeygen.GenerationResult, error) {
	if keyType != witness.Ed25519V1 {
		return nil, fmt.Errorf("Ed25519 witness generator only supports keyType %q, got %q", witness.Ed25519V1, keyType)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size for Ed25519 witness: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return saveFromSeed(paths, seed, kr)
}

func (g *WitnessEd25519Generator) GenerateFromMnemonic(_ context.Context, _ storepaths.Paths, _ string, _ *securecrypto.Keyring, keyType string, _ map[string]string) (*internalkeygen.GenerationResult, error) {
	return nil, fmt.Errorf("mnemonic import not supported for key type: %s", keyType)
}

func (g *WitnessEd25519Generator) GenerateRandom(_ context.Context, paths storepaths.Paths, kr *securecrypto.Keyring, keyType string, _ map[string]string) (*internalkeygen.GenerationResult, error) {
	if keyType != witness.Ed25519V1 {
		return nil, fmt.Errorf("Ed25519 witness generator only supports keyType %q, got %q", witness.Ed25519V1, keyType)
	}
	seed := make([]byte, ed25519.SeedSize)
	defer securecrypto.ZeroBytes(seed)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate witness key seed: %w", err)
	}
	return saveFromSeed(paths, seed, kr)
}

// saveFromSeed derives the keypair from seed and saves it; the private key
// is zeroed once saved.
func saveFromSeed(paths storepaths.Paths, seed []byte, kr *securecrypto.Keyring) (*internalkeygen.GenerationResult, error) {
	privateKey := ed25519.NewKeyFromSeed(seed)
	defer securecrypto.ZeroBytes(privateKey)
	publicKey := append([]byte(nil), privateKey.Public().(ed25519.PublicKey)...)
	return internalkeygen.SaveWitnessKey(paths, witness.Ed25519V1, publicKey, privateKey, kr)
}

// validateWitnessPair verifies an Ed25519 witness keypair with a fixed,
// domain-separated probe message, as the Falcon-1024 witness check does.
func validateWitnessPair(publicKey, privateKey []byte) error {
	if len(privateKey) != witness.Ed25519PrivateKeySize {
		return fmt.Errorf("witness private key length %d invalid (expected %d bytes)", len(privateKey), witness.Ed25519PrivateKeySize)
	}
	const probe = "APLANE_WITNESS_KEY_PAIR_V1"
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), []byte(probe))
	defer securecrypto.ZeroBytes(signature)
	if err := sigverify.Verify(sigconstruction.Ed25519(), publicKey, []byte(probe), signature); err != nil {
		return fmt.Errorf("witness public key does not match private key")
	}
	return nil
}

var registerWitnessKeygenOnce sync.Once

// RegisterWitnessKeygen registers the Ed25519 witness key type's catalog
// entry, its generator, and the pair validator used when loading
// signer-custodied witness keys, as the Falcon-1024 witness registration does.
func RegisterWitnessKeygen() {
	registerWitnessKeygenOnce.Do(func() {
		keytypecatalog.Register(keytypecatalog.Entry{
			KeyType:      witness.Ed25519V1,
			Family:       "cosigner-ed25519",
			Availability: keytypecatalog.AvailabilityDefaultEnabled,
			// A witness key is a cosigner's component key, not an account.
			// The declaration does not stop a rekey to the key's address:
			// the signer that holds the account holds no witness key.
			ValidRekeyTarget: false,
		})
		internalkeygen.Register(&WitnessEd25519Generator{})
		witness.RegisterPairValidator(witness.Ed25519V1, validateWitnessPair)
	})
}
