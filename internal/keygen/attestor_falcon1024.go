// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

const attestorFalcon1024SeedSize = 64

// AttestorFalcon1024Generator creates raw Falcon-1024 attestor component keys.
// These keys are not Algorand spending accounts and are intentionally
// registered only under their exact component key type.
type AttestorFalcon1024Generator struct {
	ops *signerops.Ops
}

func (g *AttestorFalcon1024Generator) Family() string {
	return keytypes.SentryComponentFalcon1024V1
}

func (g *AttestorFalcon1024Generator) GenerateFromSeed(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != keytypes.SentryComponentFalcon1024V1 {
		return nil, fmt.Errorf("attestor Falcon-1024 generator only supports keyType %q, got %q", keytypes.SentryComponentFalcon1024V1, keyType)
	}
	if len(seed) != attestorFalcon1024SeedSize {
		return nil, fmt.Errorf("invalid seed size for attestor Falcon-1024: expected %d bytes, got %d", attestorFalcon1024SeedSize, len(seed))
	}

	seedCopy := append([]byte(nil), seed...)
	defer securecrypto.ZeroBytes(seedCopy)

	ops := g.ops
	if ops == nil {
		ops = signerops.New(nil)
	}
	publicKey, privateKey, err := ops.GenerateKeypair(seedCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate component key: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	return saveAttestorComponentKey(paths, identityID, keyType, publicKey, privateKey, masterKey)
}

func (g *AttestorFalcon1024Generator) GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, identityID string, mnemonic string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = paths
	_ = identityID
	_ = mnemonic
	_ = masterKey
	_ = params
	return nil, fmt.Errorf("mnemonic import not supported for key type: %s", keyType)
}

func (g *AttestorFalcon1024Generator) GenerateRandom(ctx context.Context, paths storepaths.Paths, identityID string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	_ = params
	if keyType != keytypes.SentryComponentFalcon1024V1 {
		return nil, fmt.Errorf("attestor Falcon-1024 generator only supports keyType %q, got %q", keytypes.SentryComponentFalcon1024V1, keyType)
	}

	seed := make([]byte, attestorFalcon1024SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate component seed: %w", err)
	}
	defer securecrypto.ZeroBytes(seed)

	ops := g.ops
	if ops == nil {
		ops = signerops.New(nil)
	}
	publicKey, privateKey, err := ops.GenerateKeypair(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate component key: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey)

	return saveAttestorComponentKey(paths, identityID, keyType, publicKey, privateKey, masterKey)
}

func saveAttestorComponentKey(paths storepaths.Paths, identityID, keyType string, publicKey, privateKey []byte, masterKey []byte) (*GenerationResult, error) {
	componentKey, err := keytypes.ComponentKeySelector(keyType, publicKey)
	if err != nil {
		return nil, err
	}

	keyPair := &keys.KeyPair{
		Category:      keys.CategoryComponent,
		KeyType:       keyType,
		PublicKeyHex:  fmt.Sprintf("%x", publicKey),
		PrivateKeyHex: fmt.Sprintf("%x", privateKey),
	}
	keyFiles, err := keys.SaveKeyFile(paths, keyPair, identityID, componentKey, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to save component key: %w", err)
	}

	return &GenerationResult{
		Address:      componentKey,
		KeyType:      keyType,
		PublicKeyHex: keyPair.PublicKeyHex,
		KeyFiles:     keyFiles,
	}, nil
}

var registerAttestorFalcon1024GeneratorOnce sync.Once

// RegisterAttestorFalcon1024Generator registers the component-key generator.
// This is intentionally separate from the transaction-signing provider
// registry.
func RegisterAttestorFalcon1024Generator() {
	registerAttestorFalcon1024GeneratorOnce.Do(func() {
		Register(&AttestorFalcon1024Generator{})
	})
}
