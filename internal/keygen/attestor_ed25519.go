// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"

	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// AttestorEd25519Generator creates raw Ed25519 attestor component keys. These
// keys are not Algorand spending accounts and are intentionally registered only
// under their exact component key type.
type AttestorEd25519Generator struct{}

func (g *AttestorEd25519Generator) Family() string {
	return keytypes.AttestorComponentEd25519V1
}

func (g *AttestorEd25519Generator) GenerateFromSeed(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != keytypes.AttestorComponentEd25519V1 {
		return nil, fmt.Errorf("attestor Ed25519 generator only supports keyType %q, got %q", keytypes.AttestorComponentEd25519V1, keyType)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size for attestor Ed25519: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	defer securecrypto.ZeroBytes(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return saveAttestorComponentKey(paths, identityID, keyType, publicKey, privateKey, masterKey)
}

func (g *AttestorEd25519Generator) GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, identityID string, mnemonic string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = paths
	_ = identityID
	_ = mnemonic
	_ = masterKey
	_ = params
	return nil, fmt.Errorf("mnemonic import not supported for key type: %s", keyType)
}

func (g *AttestorEd25519Generator) GenerateRandom(ctx context.Context, paths storepaths.Paths, identityID string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != keytypes.AttestorComponentEd25519V1 {
		return nil, fmt.Errorf("attestor Ed25519 generator only supports keyType %q, got %q", keytypes.AttestorComponentEd25519V1, keyType)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate component key: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	return saveAttestorComponentKey(paths, identityID, keyType, publicKey, privateKey, masterKey)
}

var registerAttestorEd25519GeneratorOnce sync.Once

// RegisterAttestorEd25519Generator registers the component-key generator. This
// is intentionally separate from the transaction-signing provider registry.
func RegisterAttestorEd25519Generator() {
	registerAttestorEd25519GeneratorOnce.Do(func() {
		Register(&AttestorEd25519Generator{})
	})
}
