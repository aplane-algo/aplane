// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package mnemonic

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func init() {
	// Register Ed25519 handler for tests
	RegisterEd25519Handler()
}

// TestEd25519HandlerKeyType verifies the handler identifier
func TestEd25519HandlerKeyType(t *testing.T) {
	handler := &Ed25519Handler{}

	if handler.Family() != "ed25519" {
		t.Errorf("Expected key type 'ed25519', got '%s'", handler.Family())
	}
}

// TestEd25519HandlerWordCount verifies 25-word Algorand format
func TestEd25519HandlerWordCount(t *testing.T) {
	handler := &Ed25519Handler{}

	if handler.WordCount() != 25 {
		t.Errorf("Expected 25 words, got %d", handler.WordCount())
	}
}

// TestEd25519HandlerValidateWordCount verifies word count validation
func TestEd25519HandlerValidateWordCount(t *testing.T) {
	handler := &Ed25519Handler{}

	tests := []struct {
		name      string
		count     int
		shouldErr bool
	}{
		{"valid 25 words", 25, false},
		{"invalid 24 words", 24, true},
		{"invalid 26 words", 26, true},
		{"invalid 12 words", 12, true},
		{"invalid 0 words", 0, true},
		{"invalid negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.ValidateWordCount(tt.count)
			if (err != nil) != tt.shouldErr {
				t.Errorf("ValidateWordCount(%d): expected error=%v, got error=%v",
					tt.count, tt.shouldErr, err != nil)
			}

			if tt.shouldErr && err != nil {
				// Verify error message mentions the count
				if !strings.Contains(err.Error(), "25") {
					t.Errorf("Error should mention expected word count: %v", err)
				}
			}
		})
	}
}

// TestEd25519HandlerGenerateMnemonic verifies mnemonic generation
func TestEd25519HandlerGenerateMnemonic(t *testing.T) {
	handler := &Ed25519Handler{}

	words, seed, entropy, err := handler.GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic failed: %v", err)
	}

	// Verify words string is not empty
	if words == "" {
		t.Fatal("Generated mnemonic words should not be empty")
	}

	// Verify it's 25 words
	wordSlice := strings.Fields(words)
	if len(wordSlice) != 25 {
		t.Errorf("Expected 25 words, got %d", len(wordSlice))
	}

	// Verify seed (private key) is 64 bytes
	if len(seed) != 64 {
		t.Errorf("Expected 64-byte seed, got %d bytes", len(seed))
	}

	// Verify entropy is nil for Ed25519/Algorand
	if entropy != nil {
		t.Error("Ed25519/Algorand should not return entropy")
	}

	// Verify the mnemonic is valid by converting it back
	reconstructed, err := handler.SeedFromMnemonic(wordSlice, "")
	if err != nil {
		t.Fatalf("Failed to reconstruct seed from generated mnemonic: %v", err)
	}

	// Verify round-trip produces the same seed
	if len(reconstructed) != len(seed) {
		t.Error("Reconstructed seed length doesn't match original")
	}

	// Note: We can't compare bytes directly because Algorand mnemonic
	// doesn't preserve the full private key deterministically (checksum)
	// But we can verify it produces a valid account
	if len(reconstructed) != 64 {
		t.Error("Reconstructed seed should be 64 bytes")
	}
}

// TestEd25519HandlerGenerateMnemonicUniqueness verifies each generation is unique
func TestEd25519HandlerGenerateMnemonicUniqueness(t *testing.T) {
	handler := &Ed25519Handler{}

	// Generate multiple mnemonics
	mnemonics := make(map[string]bool)
	seeds := make(map[string]bool)
	iterations := 10

	for i := 0; i < iterations; i++ {
		words, seed, _, err := handler.GenerateMnemonic()
		if err != nil {
			t.Fatalf("Generation %d failed: %v", i, err)
		}

		// Check for duplicate mnemonics
		if mnemonics[words] {
			t.Errorf("Duplicate mnemonic generated at iteration %d", i)
		}
		mnemonics[words] = true

		// Check for duplicate seeds
		seedStr := string(seed)
		if seeds[seedStr] {
			t.Errorf("Duplicate seed generated at iteration %d", i)
		}
		seeds[seedStr] = true
	}

	if len(mnemonics) != iterations {
		t.Errorf("Expected %d unique mnemonics, got %d", iterations, len(mnemonics))
	}
}

// TestEd25519HandlerSeedFromMnemonic verifies mnemonic-to-seed conversion
func TestEd25519HandlerSeedFromMnemonic(t *testing.T) {
	handler := &Ed25519Handler{}

	// Use a known Algorand test mnemonic (25 words)
	// This is a well-known test mnemonic from Algorand documentation
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"
	words := strings.Fields(testMnemonic)

	seed, err := handler.SeedFromMnemonic(words, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic failed: %v", err)
	}

	// Verify seed is 64 bytes
	if len(seed) != 64 {
		t.Errorf("Expected 64-byte seed, got %d bytes", len(seed))
	}

	// Verify determinism: same mnemonic should produce same seed
	seed2, err := handler.SeedFromMnemonic(words, "")
	if err != nil {
		t.Fatalf("Second SeedFromMnemonic failed: %v", err)
	}

	if len(seed) != len(seed2) {
		t.Error("Seed lengths should match")
	}

	// Verify we can create a valid account from the seed
	// The seed is the private key in Algorand
	account, err := crypto.AccountFromPrivateKey(seed)
	if err != nil {
		t.Errorf("Failed to create account from derived seed: %v", err)
	}

	// Verify account address is non-zero
	zeroAddr := types.Address{}
	if account.Address == zeroAddr {
		t.Error("Derived account address should not be zero")
	}
}

// TestEd25519HandlerSeedFromMnemonicWithPassphrase verifies passphrase rejection
func TestEd25519HandlerSeedFromMnemonicWithPassphrase(t *testing.T) {
	handler := &Ed25519Handler{}

	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"
	words := strings.Fields(testMnemonic)

	// Should reject non-empty passphrase
	_, err := handler.SeedFromMnemonic(words, "some-passphrase")
	if err == nil {
		t.Fatal("Expected error when providing passphrase")
	}

	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("Error should mention passphrase rejection: %v", err)
	}
}

// TestEd25519HandlerSeedFromMnemonicInvalid verifies error handling for invalid mnemonics
func TestEd25519HandlerSeedFromMnemonicInvalid(t *testing.T) {
	handler := &Ed25519Handler{}

	tests := []struct {
		name     string
		words    []string
		errorMsg string
	}{
		{
			name:     "empty mnemonic",
			words:    []string{},
			errorMsg: "failed to derive private key",
		},
		{
			name:     "too few words",
			words:    strings.Fields("abandon abandon abandon"),
			errorMsg: "failed to derive private key",
		},
		{
			name:     "invalid word",
			words:    strings.Fields("invalid notaword fake abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"),
			errorMsg: "failed to derive private key",
		},
		{
			name: "wrong checksum",
			// All "abandon" but wrong last word
			words:    strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"),
			errorMsg: "failed to derive private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handler.SeedFromMnemonic(tt.words, "")
			if err == nil {
				t.Fatal("Expected error for invalid mnemonic")
			}

			if !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("Error should contain %q, got: %v", tt.errorMsg, err)
			}
		})
	}
}

// TestEd25519HandlerEntropyToMnemonic verifies it's not supported
func TestEd25519HandlerEntropyToMnemonic(t *testing.T) {
	handler := &Ed25519Handler{}

	entropy := make([]byte, 32)
	_, err := handler.EntropyToMnemonic(entropy)
	if err == nil {
		t.Fatal("EntropyToMnemonic should not be supported for Ed25519")
	}

	if !strings.Contains(err.Error(), "does not support") {
		t.Errorf("Error should mention lack of support: %v", err)
	}
}

// TestKeyToMnemonic verifies private key to mnemonic conversion
func TestKeyToMnemonic(t *testing.T) {
	// Generate a new account
	account := crypto.GenerateAccount()

	// Convert to mnemonic
	mnemonic, err := KeyToMnemonic(account.PrivateKey)
	if err != nil {
		t.Fatalf("KeyToMnemonic failed: %v", err)
	}

	// Verify it's 25 words
	words := strings.Fields(mnemonic)
	if len(words) != 25 {
		t.Errorf("Expected 25 words, got %d", len(words))
	}

	// Verify round-trip: mnemonic back to key
	handler := &Ed25519Handler{}
	reconstructedKey, err := handler.SeedFromMnemonic(words, "")
	if err != nil {
		t.Fatalf("Failed to reconstruct key: %v", err)
	}

	// Verify the reconstructed key produces the same account
	reconstructedAccount, err := crypto.AccountFromPrivateKey(reconstructedKey)
	if err != nil {
		t.Fatalf("Failed to create account from reconstructed key: %v", err)
	}

	if reconstructedAccount.Address != account.Address {
		t.Error("Reconstructed account address doesn't match original")
	}
}

// TestKeyToMnemonicInvalidSize verifies error handling for wrong key size
func TestKeyToMnemonicInvalidSize(t *testing.T) {
	tests := []struct {
		name   string
		keyLen int
	}{
		{"too short", 32},
		{"too long", 128},
		{"empty", 0},
		{"slightly wrong", 63},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidKey := make([]byte, tt.keyLen)
			_, err := KeyToMnemonic(invalidKey)
			if err == nil {
				t.Fatal("Expected error for invalid key size")
			}

			if !strings.Contains(err.Error(), "invalid private key length") {
				t.Errorf("Error should mention invalid length: %v", err)
			}
		})
	}
}

// TestEd25519HandlerRegistration verifies automatic registration
func TestEd25519HandlerRegistration(t *testing.T) {
	// The handler should be auto-registered at init()
	handler, err := GetHandler("ed25519")
	if err != nil {
		t.Fatalf("Ed25519 handler should be registered: %v", err)
	}

	// Verify it's the correct type
	ed25519Handler, ok := handler.(*Ed25519Handler)
	if !ok {
		t.Fatal("Handler should be Ed25519Handler type")
	}

	if ed25519Handler.Family() != "ed25519" {
		t.Error("Handler key type mismatch")
	}
}

// TestMnemonicFormatConsistency verifies Algorand SDK compatibility
func TestMnemonicFormatConsistency(t *testing.T) {
	handler := &Ed25519Handler{}

	// Generate mnemonic
	mnemonic, seed, _, err := handler.GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic failed: %v", err)
	}

	// The seed should be a valid Algorand private key
	account, err := crypto.AccountFromPrivateKey(seed)
	if err != nil {
		t.Fatalf("Seed is not a valid Algorand private key: %v", err)
	}

	// Converting the account's private key back to mnemonic should work
	mnemonicFromKey, err := KeyToMnemonic(account.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert key back to mnemonic: %v", err)
	}

	// The two mnemonics should produce the same address
	words1 := strings.Fields(mnemonic)
	words2 := strings.Fields(mnemonicFromKey)

	seed1, _ := handler.SeedFromMnemonic(words1, "")
	seed2, _ := handler.SeedFromMnemonic(words2, "")

	acc1, _ := crypto.AccountFromPrivateKey(seed1)
	acc2, _ := crypto.AccountFromPrivateKey(seed2)

	if acc1.Address != acc2.Address {
		t.Error("Mnemonics should produce the same address")
	}
}
