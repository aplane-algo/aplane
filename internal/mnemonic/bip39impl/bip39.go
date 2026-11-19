// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package bip39impl

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/mnemonic"

	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// BIP39Handler is the Falcon BIP-39 mnemonic handler. It wraps the
// falcon-signatures/mnemonic helper, which takes 24 BIP-39 words over 32
// bytes of entropy and derives the Falcon seed from them, and exposes it
// through the aplane Handler interface under the given family name.
type BIP39Handler struct {
	family string
}

// The falcon-signatures helper accepts only this strength.
const (
	wordCount    = 24
	entropyBytes = 32
)

var _ mnemonic.Handler = (*BIP39Handler)(nil)

// NewHandler returns the BIP-39 handler for family.
func NewHandler(family string) *BIP39Handler {
	return &BIP39Handler{family: family}
}

func (h *BIP39Handler) RoutingFamily() string { return h.family }

// GenerateMnemonic generates a fresh 24-word BIP-39 mnemonic. Returns joined
// words, derived seed, and the underlying entropy (useful for key files that
// want to re-export the mnemonic later).
// On every error path the fresh entropy is zeroed before it is dropped.
func (h *BIP39Handler) GenerateMnemonic() (words string, seed []byte, entropy []byte, err error) {
	entropy = make([]byte, entropyBytes)
	if _, err := readEntropy(entropy); err != nil {
		crypto.ZeroBytes(entropy)
		return "", nil, nil, fmt.Errorf("failed to generate entropy: %w", err)
	}

	mnemonicWords, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		crypto.ZeroBytes(entropy)
		return "", nil, nil, fmt.Errorf("failed to generate mnemonic from entropy: %w", err)
	}

	seedArray, err := falconmnemonic.SeedFromMnemonic(mnemonicWords, "")
	if err != nil {
		crypto.ZeroBytes(entropy)
		return "", nil, nil, fmt.Errorf("failed to generate seed from mnemonic: %w", err)
	}

	return strings.Join(mnemonicWords, " "), seedArray[:], entropy, nil
}

// readEntropy fills fresh mnemonic entropy. Tests replace it to watch the
// buffer.
var readEntropy = rand.Read

// SeedFromMnemonic derives a BIP-39 seed from the given words. The
// passphrase is the standard BIP-39 passphrase (may be empty).
func (h *BIP39Handler) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	seedArray, err := falconmnemonic.SeedFromMnemonic(words, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}
	return seedArray[:], nil
}

// EntropyToMnemonic converts raw entropy bytes to BIP-39 words. Returns
// the words joined by spaces.
func (h *BIP39Handler) EntropyToMnemonic(entropy []byte) (string, error) {
	words, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}
	return strings.Join(words, " "), nil
}

// WordCount returns the expected word count for this handler.
func (h *BIP39Handler) WordCount() int { return wordCount }
