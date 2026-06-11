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

// SentryEd25519Generator creates raw Ed25519 sentry keys. These keys are not
// Algorand spending accounts and are intentionally registered only under their
// exact sentry key type.
type SentryEd25519Generator struct{}

func (g *SentryEd25519Generator) Family() string {
	return keytypes.SentryComponentEd25519V1
}

func (g *SentryEd25519Generator) GenerateFromSeed(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != keytypes.SentryComponentEd25519V1 {
		return nil, fmt.Errorf("sentry Ed25519 generator only supports keyType %q, got %q", keytypes.SentryComponentEd25519V1, keyType)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size for sentry Ed25519: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	defer securecrypto.ZeroBytes(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return SaveSentryComponentKey(paths, identityID, keyType, publicKey, privateKey, masterKey)
}

func (g *SentryEd25519Generator) GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, identityID string, mnemonic string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = paths
	_ = identityID
	_ = mnemonic
	_ = masterKey
	_ = params
	return nil, fmt.Errorf("mnemonic import not supported for key type: %s", keyType)
}

func (g *SentryEd25519Generator) GenerateRandom(ctx context.Context, paths storepaths.Paths, identityID string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != keytypes.SentryComponentEd25519V1 {
		return nil, fmt.Errorf("sentry Ed25519 generator only supports keyType %q, got %q", keytypes.SentryComponentEd25519V1, keyType)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sentry key: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	return SaveSentryComponentKey(paths, identityID, keyType, publicKey, privateKey, masterKey)
}

var registerSentryEd25519GeneratorOnce sync.Once

// RegisterSentryEd25519Generator registers the sentry-key generator. This
// is intentionally separate from the transaction-signing provider registry.
func RegisterSentryEd25519Generator() {
	registerSentryEd25519GeneratorOnce.Do(func() {
		Register(&SentryEd25519Generator{})
	})
}
