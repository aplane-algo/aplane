// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	internalkeygen "github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

const witnessFalcon1024SeedSize = 64

// WitnessFalcon1024Generator creates raw Falcon-1024 witness keys.
// These keys are not Algorand spending accounts and are intentionally
// registered only under their exact witness key type.
type WitnessFalcon1024Generator struct {
	ops *signerops.Ops
}

func (g *WitnessFalcon1024Generator) RoutingFamily() string {
	return witness.Falcon1024V1
}

func (g *WitnessFalcon1024Generator) GenerateFromSeed(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, kr *securecrypto.Keyring, keyType string, params map[string]string) (*internalkeygen.GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != witness.Falcon1024V1 {
		return nil, fmt.Errorf("Falcon-1024 witness generator only supports keyType %q, got %q", witness.Falcon1024V1, keyType)
	}
	if len(seed) != witnessFalcon1024SeedSize {
		return nil, fmt.Errorf("invalid seed size for Falcon-1024 witness: expected %d bytes, got %d", witnessFalcon1024SeedSize, len(seed))
	}

	seedCopy := append([]byte(nil), seed...)
	defer securecrypto.ZeroBytes(seedCopy)

	publicKey, privateKey, err := g.signerOps().GenerateKeypair(seedCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate witness key: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	return internalkeygen.SaveWitnessKey(paths, identityID, keyType, publicKey, privateKey, kr)
}

func (g *WitnessFalcon1024Generator) GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, identityID string, mnemonic string, kr *securecrypto.Keyring, keyType string, params map[string]string) (*internalkeygen.GenerationResult, error) {
	_ = ctx
	_ = paths
	_ = identityID
	_ = mnemonic
	_ = kr
	_ = params
	return nil, fmt.Errorf("mnemonic import not supported for key type: %s", keyType)
}

func (g *WitnessFalcon1024Generator) GenerateRandom(ctx context.Context, paths storepaths.Paths, identityID string, kr *securecrypto.Keyring, keyType string, params map[string]string) (*internalkeygen.GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != witness.Falcon1024V1 {
		return nil, fmt.Errorf("Falcon-1024 witness generator only supports keyType %q, got %q", witness.Falcon1024V1, keyType)
	}

	seed := make([]byte, witnessFalcon1024SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate witness key seed: %w", err)
	}
	defer securecrypto.ZeroBytes(seed)

	publicKey, privateKey, err := g.signerOps().GenerateKeypair(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate witness key: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	return internalkeygen.SaveWitnessKey(paths, identityID, keyType, publicKey, privateKey, kr)
}

func (g *WitnessFalcon1024Generator) signerOps() *signerops.Ops {
	if g.ops != nil {
		return g.ops
	}
	return signerops.New(nil)
}

// validateWitnessPair verifies a Falcon-1024 witness keypair with a fixed,
// domain-separated probe message.
func validateWitnessPair(publicKey, privateKey []byte) error {
	const probe = "APLANE_WITNESS_KEY_PAIR_V1"
	signature, err := signerops.New(nil).Sign(privateKey, []byte(probe))
	if err != nil {
		return fmt.Errorf("witness public/private key validation failed: %w", err)
	}
	defer securecrypto.ZeroBytes(signature)
	if err := verify.VerifyFalcon1024(publicKey, []byte(probe), signature); err != nil {
		return fmt.Errorf("witness public key does not match private key")
	}
	return nil
}

var registerWitnessKeygenOnce sync.Once

// RegisterWitnessKeygen registers the Falcon-1024 witness generator and pair
// validator used when loading signer-custodied witness keys. This is
// intentionally separate from the transaction-signing provider registry.
func RegisterWitnessKeygen() {
	registerWitnessKeygenOnce.Do(func() {
		internalkeygen.Register(&WitnessFalcon1024Generator{})
		witness.RegisterPairValidator(witness.Falcon1024V1, validateWitnessPair)
	})
}
