// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/algorand/falcon"
	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// NativeFalconGenerator creates protocol-native Falcon-1024 account keys.
type NativeFalconGenerator struct{}

func (*NativeFalconGenerator) RoutingFamily() string { return nativefalcon.KeyType }

func (g *NativeFalconGenerator) GenerateFromSeed(ctx context.Context, paths storepaths.Paths, entropy []byte, kr *securecrypto.Keyring, keyType string, params map[string]string) (*GenerationResult, error) {
	_ = ctx
	if keyType != nativefalcon.KeyType {
		return nil, fmt.Errorf("native Falcon generator only supports keyType %q, got %q", nativefalcon.KeyType, keyType)
	}
	if len(params) != 0 {
		return nil, fmt.Errorf("%w: native Falcon accepts no creation parameters", ErrInvalidParams)
	}
	if len(entropy) != nativefalcon.RecoveryEntropySize {
		return nil, fmt.Errorf("native Falcon recovery entropy length %d, want %d", len(entropy), nativefalcon.RecoveryEntropySize)
	}
	ownedEntropy := append([]byte(nil), entropy...)
	defer securecrypto.ZeroBytes(ownedEntropy)
	return g.generate(paths, ownedEntropy, kr, "")
}

func (g *NativeFalconGenerator) GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, words string, kr *securecrypto.Keyring, keyType string, params map[string]string) (*GenerationResult, error) {
	if len(strings.Fields(words)) != nativefalcon.MnemonicWordCount {
		return nil, fmt.Errorf("native Falcon requires exactly %d mnemonic words", nativefalcon.MnemonicWordCount)
	}
	entropy, err := algomnemonic.ToKey(words)
	if err != nil {
		return nil, fmt.Errorf("decode native Falcon mnemonic: %w", err)
	}
	defer securecrypto.ZeroBytes(entropy)
	result, err := g.GenerateFromSeed(ctx, paths, entropy, kr, keyType, params)
	if err != nil {
		return nil, err
	}
	result.Mnemonic = words
	return result, nil
}

func (g *NativeFalconGenerator) GenerateRandom(ctx context.Context, paths storepaths.Paths, kr *securecrypto.Keyring, keyType string, params map[string]string) (*GenerationResult, error) {
	entropy := make([]byte, nativefalcon.RecoveryEntropySize)
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("generate native Falcon recovery entropy: %w", err)
	}
	defer securecrypto.ZeroBytes(entropy)
	words, err := algomnemonic.FromKey(entropy)
	if err != nil {
		return nil, fmt.Errorf("encode native Falcon mnemonic: %w", err)
	}
	result, err := g.GenerateFromSeed(ctx, paths, entropy, kr, keyType, params)
	if err != nil {
		return nil, err
	}
	result.Mnemonic = words
	return result, nil
}

func (g *NativeFalconGenerator) generate(paths storepaths.Paths, entropy []byte, kr *securecrypto.Keyring, mnemonicWords string) (*GenerationResult, error) {
	seedInput := make([]byte, 0, len("PQK")+len(nativefalcon.Scheme)+len(entropy))
	seedInput = append(seedInput, "PQK"...)
	seedInput = append(seedInput, nativefalcon.Scheme...)
	seedInput = append(seedInput, entropy...)
	workingSeed := sha512.Sum512_256(seedInput)
	securecrypto.ZeroBytes(seedInput)
	defer securecrypto.ZeroBytes(workingSeed[:])

	publicKey, privateKey, err := falcon.GenerateKey(workingSeed[:])
	if err != nil {
		return nil, fmt.Errorf("generate native Falcon key pair: %w", err)
	}
	defer securecrypto.ZeroBytes(privateKey[:])
	salt, address, err := nativefalcon.CanonicalAddress(publicKey[:])
	if err != nil {
		return nil, err
	}
	payload := keys.NewNativeFalconPayload(publicKey[:], privateKey[:], salt)
	defer payload.ZeroSecrets()
	keyFiles, err := keys.SavePayload(paths, payload, kr)
	if err != nil {
		return nil, fmt.Errorf("save native Falcon key: %w", err)
	}
	return &GenerationResult{
		Address:      address.String(),
		KeyType:      nativefalcon.KeyType,
		PublicKeyHex: hex.EncodeToString(publicKey[:]),
		Mnemonic:     mnemonicWords,
		KeyFiles:     keyFiles,
	}, nil
}

var registerNativeFalconGeneratorOnce sync.Once

func RegisterNativeFalconGenerator() {
	registerNativeFalconGeneratorOnce.Do(func() { Register(&NativeFalconGenerator{}) })
}
