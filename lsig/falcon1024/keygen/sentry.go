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
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

const sentryFalcon1024SeedSize = 64

// SentryFalcon1024Generator creates raw Falcon-1024 sentry keys.
// These keys are not Algorand spending accounts and are intentionally
// registered only under their exact sentry key type.
type SentryFalcon1024Generator struct {
	ops *signerops.Ops
}

func (g *SentryFalcon1024Generator) Family() string {
	return keytypes.SentryComponentFalcon1024V1
}

func (g *SentryFalcon1024Generator) GenerateFromSeed(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, masterKey []byte, keyType string, params map[string]string) (*internalkeygen.GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != keytypes.SentryComponentFalcon1024V1 {
		return nil, fmt.Errorf("sentry Falcon-1024 generator only supports keyType %q, got %q", keytypes.SentryComponentFalcon1024V1, keyType)
	}
	if len(seed) != sentryFalcon1024SeedSize {
		return nil, fmt.Errorf("invalid seed size for sentry Falcon-1024: expected %d bytes, got %d", sentryFalcon1024SeedSize, len(seed))
	}

	seedCopy := append([]byte(nil), seed...)
	defer securecrypto.ZeroBytes(seedCopy)

	publicKey, privateKey, err := g.signerOps().GenerateKeypair(seedCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sentry key: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	return internalkeygen.SaveSentryComponentKey(paths, identityID, keyType, publicKey, privateKey, masterKey)
}

func (g *SentryFalcon1024Generator) GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, identityID string, mnemonic string, masterKey []byte, keyType string, params map[string]string) (*internalkeygen.GenerationResult, error) {
	_ = ctx
	_ = paths
	_ = identityID
	_ = mnemonic
	_ = masterKey
	_ = params
	return nil, fmt.Errorf("mnemonic import not supported for key type: %s", keyType)
}

func (g *SentryFalcon1024Generator) GenerateRandom(ctx context.Context, paths storepaths.Paths, identityID string, masterKey []byte, keyType string, params map[string]string) (*internalkeygen.GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != keytypes.SentryComponentFalcon1024V1 {
		return nil, fmt.Errorf("sentry Falcon-1024 generator only supports keyType %q, got %q", keytypes.SentryComponentFalcon1024V1, keyType)
	}

	seed := make([]byte, sentryFalcon1024SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate sentry key seed: %w", err)
	}
	defer securecrypto.ZeroBytes(seed)

	publicKey, privateKey, err := g.signerOps().GenerateKeypair(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sentry key: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	return internalkeygen.SaveSentryComponentKey(paths, identityID, keyType, publicKey, privateKey, masterKey)
}

func (g *SentryFalcon1024Generator) signerOps() *signerops.Ops {
	if g.ops != nil {
		return g.ops
	}
	return signerops.New(nil)
}

// validateSentryComponentPair verifies a Falcon-1024 sentry public/private
// pair by signing and verifying a fixed probe message.
func validateSentryComponentPair(publicKey, privateKey []byte) error {
	const probe = "APLANE_COMPONENT_KEY_LOAD_V1"
	signature, err := signerops.New(nil).Sign(privateKey, []byte(probe))
	if err != nil {
		return fmt.Errorf("sentry public/private key validation failed: %w", err)
	}
	defer securecrypto.ZeroBytes(signature)
	if err := verify.VerifyFalcon1024(publicKey, []byte(probe), signature); err != nil {
		return fmt.Errorf("sentry public key does not match private key")
	}
	return nil
}

var registerSentryComponentsOnce sync.Once

// RegisterSentryComponents registers the Falcon-1024 sentry key generator and
// the component pair validator used when loading stored sentry keys. This is
// intentionally separate from the transaction-signing provider registry.
func RegisterSentryComponents() {
	registerSentryComponentsOnce.Do(func() {
		internalkeygen.Register(&SentryFalcon1024Generator{})
		keytypes.RegisterComponentPairValidator(keytypes.SentryComponentFalcon1024V1, validateSentryComponentPair)
	})
}
