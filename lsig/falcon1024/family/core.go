// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package family

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// FalconCore contains shared Falcon-1024 cryptographic operations.
// It is embedded by version-specific implementations (Falcon1024V1, Falcon1024V2, etc.)
// to provide common functionality while allowing version-specific LogicSig derivation.
type FalconCore struct{}

// CryptoSignatureSize returns the maximum Falcon-1024 signature size in bytes.
// Used for pre-signing fee estimation.
func (c *FalconCore) CryptoSignatureSize() int {
	return MaxSignatureSize
}

// MnemonicScheme returns the mnemonic scheme used by Falcon.
func (c *FalconCore) MnemonicScheme() string {
	return MnemonicScheme
}

// MnemonicWordCount returns the expected number of mnemonic words.
func (c *FalconCore) MnemonicWordCount() int {
	return MnemonicWordCount
}

// DisplayColor returns the ANSI color code for Falcon addresses in UI.
func (c *FalconCore) DisplayColor() string {
	return DisplayColor
}

// GenerateKeypair generates a Falcon-1024 keypair from a seed.
// The seed typically comes from BIP-39 mnemonic derivation (64 bytes).
func (c *FalconCore) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Falcon keypair: %w", err)
	}
	return kp.PublicKey[:], kp.PrivateKey[:], nil
}

// Sign signs a message with a Falcon-1024 private key.
func (c *FalconCore) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	if len(privateKey) != PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			PrivateKeySize, len(privateKey))
	}

	var priv falcongo.PrivateKey
	copy(priv[:], privateKey)
	defer crypto.ZeroBytes(priv[:]) // Zero local copy after use

	// The falcongo library requires a KeyPair, so we construct one.
	// The public key is not used for signing, only verification,
	// so we leave it zero-filled.
	var pub falcongo.PublicKey
	kp := falcongo.KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}
	defer crypto.ZeroBytes(kp.PrivateKey[:]) // Zero struct copy after use

	sig, err := kp.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return sig, nil
}

// SeedFromMnemonic derives a seed from a BIP-39 mnemonic phrase.
func (c *FalconCore) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	seedArray, err := falconmnemonic.SeedFromMnemonic(words, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}
	return seedArray[:], nil
}

// EntropyToMnemonic converts entropy bytes to BIP-39 mnemonic words.
func (c *FalconCore) EntropyToMnemonic(entropy []byte) ([]string, error) {
	words, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}
	return words, nil
}
