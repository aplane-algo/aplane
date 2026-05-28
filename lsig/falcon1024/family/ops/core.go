// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ops

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// DSABase defines Falcon metadata plus signer-side operations.
type DSABase interface {
	family.DSABase
	GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error)
	Sign(privateKey []byte, message []byte) (signature []byte, err error)
	SeedFromMnemonic(words []string, passphrase string) ([]byte, error)
	EntropyToMnemonic(entropy []byte) ([]string, error)
}

// FalconBase is the signer-capable Falcon-1024 base.
var FalconBase DSABase = &falconDSABase{}

type falconDSABase struct {
	family.FalconCore
	Core
}

func (b *falconDSABase) Name() string {
	return family.Name
}

func (b *falconDSABase) PublicKeySize() int {
	return family.PublicKeySize
}

func (b *falconDSABase) PrivateKeySize() int {
	return family.PrivateKeySize
}

// Core contains Falcon-1024 signer-side cryptographic operations.
type Core struct{}

// GenerateKeypair generates a Falcon-1024 keypair from a seed.
// The seed typically comes from BIP-39 mnemonic derivation (64 bytes).
func (c *Core) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Falcon keypair: %w", err)
	}
	return kp.PublicKey[:], kp.PrivateKey[:], nil
}

// Sign signs a message with a Falcon-1024 private key.
func (c *Core) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	if len(privateKey) != family.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			family.PrivateKeySize, len(privateKey))
	}

	var priv falcongo.PrivateKey
	copy(priv[:], privateKey)
	defer crypto.ZeroBytes(priv[:])

	// The falcongo library requires a KeyPair. The public key is not used for
	// signing, so it can stay zero-filled.
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

// SeedFromMnemonic derives a seed from a BIP-39 mnemonic phrase.
func (c *Core) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	seedArray, err := falconmnemonic.SeedFromMnemonic(words, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}
	return seedArray[:], nil
}

// EntropyToMnemonic converts entropy bytes to BIP-39 mnemonic words.
func (c *Core) EntropyToMnemonic(entropy []byte) ([]string, error) {
	words, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}
	return words, nil
}
