// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package mnemonic

import (
	"fmt"
	"strings"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
)

// Ed25519Handler implements Handler for Ed25519 using Algorand mnemonic format
type Ed25519Handler struct{}

// Family returns the algorithm family this handler supports
func (h *Ed25519Handler) Family() string {
	return "ed25519"
}

// GenerateMnemonic generates a new Algorand mnemonic (25 words)
func (h *Ed25519Handler) GenerateMnemonic() (words string, seed []byte, entropy []byte, err error) {
	// Generate Ed25519 account using Algorand SDK
	account := crypto.GenerateAccount()

	// Convert private key to 25-word mnemonic (standard Algorand format)
	mnemonicStr, err := algomnemonic.FromPrivateKey(account.PrivateKey)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// For Ed25519, the "seed" is the private key itself
	// No separate entropy in Algorand's scheme
	return mnemonicStr, account.PrivateKey, nil, nil
}

// SeedFromMnemonic derives a private key from Algorand mnemonic words
func (h *Ed25519Handler) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	// Algorand mnemonics don't use passphrases
	if passphrase != "" {
		return nil, fmt.Errorf("Ed25519/Algorand mnemonics do not support passphrases")
	}

	// Join words and derive private key
	mnemonicStr := strings.Join(words, " ")
	privateKey, err := algomnemonic.ToPrivateKey(mnemonicStr)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key from mnemonic: %w", err)
	}

	return privateKey, nil
}

// EntropyToMnemonic is not supported for Ed25519/Algorand
func (h *Ed25519Handler) EntropyToMnemonic(_ []byte) (string, error) {
	return "", fmt.Errorf("Ed25519/Algorand does not support entropy-to-mnemonic conversion")
}

// ValidateWordCount checks if the word count is valid (25 for Ed25519/Algorand)
func (h *Ed25519Handler) ValidateWordCount(wordCount int) error {
	if wordCount != 25 {
		return fmt.Errorf("ed25519 requires exactly 25 words, got %d", wordCount)
	}
	return nil
}

// WordCount returns the expected number of words (25 for Ed25519/Algorand)
func (h *Ed25519Handler) WordCount() int {
	return 25
}

// KeyToMnemonic converts an Ed25519 private key to Algorand mnemonic
// This is a helper for exporting existing keys
func KeyToMnemonic(privateKey []byte) (string, error) {
	// Algorand SDK expects 64-byte private keys
	if len(privateKey) != 64 {
		return "", fmt.Errorf("invalid private key length: expected 64 bytes, got %d", len(privateKey))
	}

	return algomnemonic.FromPrivateKey(privateKey)
}

var registerEd25519HandlerOnce sync.Once

// RegisterEd25519Handler registers the Ed25519 mnemonic handler.
// This is idempotent and safe to call multiple times.
func RegisterEd25519Handler() {
	registerEd25519HandlerOnce.Do(func() {
		Register(&Ed25519Handler{})
	})
}
