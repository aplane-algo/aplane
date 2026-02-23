// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package family

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// DSABase defines the interface for a Falcon DSA base provider.
// It exposes the cryptographic primitives and metadata needed by composed
// LogicSigs (ComposedDSA) that live in sub-packages (e.g., v1/).
type DSABase interface {
	Name() string
	PublicKeySize() int
	PrivateKeySize() int
	CryptoSignatureSize() int
	MnemonicScheme() string
	MnemonicWordCount() int
	DisplayColor() string
	GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error)
	Sign(privateKey []byte, message []byte) (signature []byte, err error)
	SeedFromMnemonic(words []string, passphrase string) ([]byte, error)
	EntropyToMnemonic(entropy []byte) ([]string, error)
}

// FalconBase is the Falcon-1024 DSA base for composed LogicSigs.
// It provides the cryptographic primitives and metadata for Falcon-1024
// signature verification.
var FalconBase DSABase = &falconDSABase{}

type falconDSABase struct{}

func (b *falconDSABase) Name() string {
	return Name
}

func (b *falconDSABase) PublicKeySize() int {
	return PublicKeySize
}

func (b *falconDSABase) PrivateKeySize() int {
	return PrivateKeySize
}

func (b *falconDSABase) CryptoSignatureSize() int {
	return MaxSignatureSize
}

func (b *falconDSABase) MnemonicScheme() string {
	return MnemonicScheme
}

func (b *falconDSABase) MnemonicWordCount() int {
	return MnemonicWordCount
}

func (b *falconDSABase) DisplayColor() string {
	return DisplayColor
}

func (b *falconDSABase) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Falcon keypair: %w", err)
	}
	return kp.PublicKey[:], kp.PrivateKey[:], nil
}

func (b *falconDSABase) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	if len(privateKey) != PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			PrivateKeySize, len(privateKey))
	}

	var priv falcongo.PrivateKey
	copy(priv[:], privateKey)
	defer crypto.ZeroBytes(priv[:])

	var pub falcongo.PublicKey
	kp := falcongo.KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}
	defer crypto.ZeroBytes(kp.PrivateKey[:])

	sig, err := kp.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return sig, nil
}

func (b *falconDSABase) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	seedArray, err := falconmnemonic.SeedFromMnemonic(words, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}
	return seedArray[:], nil
}

func (b *falconDSABase) EntropyToMnemonic(entropy []byte) ([]string, error) {
	words, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}
	return words, nil
}
