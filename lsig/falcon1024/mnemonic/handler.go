// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package mnemonic

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/mnemonic"

	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// FalconHandler implements MnemonicHandler for Falcon-1024 using BIP-39.
// The family can be overridden to allow alias registrations (e.g., hybrid families).
type FalconHandler struct {
	family string
}

// NewFalconHandler returns a Falcon mnemonic handler for the specified family.
func NewFalconHandler(family string) *FalconHandler {
	return &FalconHandler{family: family}
}

// Family returns the algorithm family this handler supports
func (h *FalconHandler) Family() string {
	if h.family == "" {
		return "falcon1024"
	}
	return h.family
}

// GenerateMnemonic generates a new BIP-39 mnemonic (24 words)
func (h *FalconHandler) GenerateMnemonic() (words string, seed []byte, entropy []byte, err error) {
	// Generate 256 bits of entropy (24 words)
	entropy = make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate entropy: %w", err)
	}

	// Convert entropy to mnemonic
	mnemonicWords, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate mnemonic from entropy: %w", err)
	}

	// Generate seed from mnemonic (no passphrase for Falcon standard)
	seedArray, err := falconmnemonic.SeedFromMnemonic(mnemonicWords, "")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate seed from mnemonic: %w", err)
	}

	return strings.Join(mnemonicWords, " "), seedArray[:], entropy, nil
}

// SeedFromMnemonic derives a seed from BIP-39 mnemonic words
func (h *FalconHandler) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	// Falcon uses BIP-39 standard derivation
	seedArray, err := falconmnemonic.SeedFromMnemonic(words, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}
	return seedArray[:], nil
}

// EntropyToMnemonic converts entropy bytes to BIP-39 mnemonic words
func (h *FalconHandler) EntropyToMnemonic(entropy []byte) (string, error) {
	words, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}
	return strings.Join(words, " "), nil
}

// ValidateWordCount checks if the word count is valid (24 for Falcon)
func (h *FalconHandler) ValidateWordCount(wordCount int) error {
	if wordCount != 24 {
		return fmt.Errorf("falcon1024 requires exactly 24 words, got %d", wordCount)
	}
	return nil
}

// WordCount returns the expected number of words (24 for Falcon)
func (h *FalconHandler) WordCount() int {
	return 24
}

var registerHandlerOnce sync.Once

// RegisterHandler registers the Falcon mnemonic handler with the mnemonic registry.
// This is idempotent and safe to call multiple times.
func RegisterHandler() {
	registerHandlerOnce.Do(func() {
		mnemonic.Register(NewFalconHandler("falcon1024"))
	})
}
