// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package bip39impl

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/mnemonic"

	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// BIP39Handler is a generic BIP-39 mnemonic handler. It wraps the BIP-39
// seed derivation provided by the falcon-signatures/mnemonic helper (which
// is a standards-compliant BIP-39 implementation) and exposes it through
// the aplane Handler interface. A single handler instance is parameterized
// by family name and word count so key-type families that share the BIP-39
// scheme (falcon1024, falcon1024_ed25519, ecdsak1) can reuse one
// implementation instead of each carrying a near-duplicate copy.
//
// Only the 24-word / 256-bit-entropy strength has been exercised in
// production so far, but the entropy-size math is derived from the word
// count, so 12/15/18/21-word handlers work too if we ever need them.
type BIP39Handler struct {
	family    string
	wordCount int
}

var _ mnemonic.Handler = (*BIP39Handler)(nil)

// NewHandler returns a BIP-39 handler for the given family using the
// specified word count. wordCount must be one of the BIP-39 valid sizes
// (12, 15, 18, 21, 24).
func NewHandler(family string, wordCount int) *BIP39Handler {
	return &BIP39Handler{family: family, wordCount: wordCount}
}

func (h *BIP39Handler) Family() string { return h.family }

// entropyBytes returns the BIP-39 entropy size for the handler's word count.
// Per BIP-39: entropyBits = wordCount * 32 / 3, and wordCount is always a
// multiple of 3 for valid sizes, so the division is exact.
func (h *BIP39Handler) entropyBytes() int {
	return (h.wordCount * 32 / 3) / 8
}

// GenerateMnemonic generates a fresh BIP-39 mnemonic of the handler's
// configured word count. Returns joined words, derived seed, and the
// underlying entropy (useful for key files that want to re-export the
// mnemonic later).
func (h *BIP39Handler) GenerateMnemonic() (words string, seed []byte, entropy []byte, err error) {
	entropy = make([]byte, h.entropyBytes())
	if _, err := rand.Read(entropy); err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate entropy: %w", err)
	}

	mnemonicWords, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate mnemonic from entropy: %w", err)
	}

	seedArray, err := falconmnemonic.SeedFromMnemonic(mnemonicWords, "")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate seed from mnemonic: %w", err)
	}

	return strings.Join(mnemonicWords, " "), seedArray[:], entropy, nil
}

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

// ValidateWordCount checks the given count against the handler's configured
// word count. Error messages carry the family name so users importing an
// ecdsak1 key don't see "falcon1024 requires exactly ..." style messages.
func (h *BIP39Handler) ValidateWordCount(wordCount int) error {
	if wordCount != h.wordCount {
		return fmt.Errorf("%s requires exactly %d words, got %d", h.family, h.wordCount, wordCount)
	}
	return nil
}

// WordCount returns the expected word count for this handler.
func (h *BIP39Handler) WordCount() int { return h.wordCount }
