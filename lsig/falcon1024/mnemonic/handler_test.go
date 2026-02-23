// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package mnemonic

import (
	"strings"
	"testing"
)

func TestFalconHandler_KeyType(t *testing.T) {
	h := &FalconHandler{}
	if h.Family() != "falcon1024" {
		t.Errorf("KeyType() = %v, want falcon1024", h.Family())
	}
}

func TestFalconHandler_WordCount(t *testing.T) {
	h := &FalconHandler{}
	if h.WordCount() != 24 {
		t.Errorf("WordCount() = %v, want 24", h.WordCount())
	}
}

func TestFalconHandler_ValidateWordCount(t *testing.T) {
	h := &FalconHandler{}

	tests := []struct {
		name      string
		wordCount int
		wantErr   bool
	}{
		{"valid 24 words", 24, false},
		{"too few 12", 12, true},
		{"too few 23", 23, true},
		{"too many 25", 25, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.ValidateWordCount(tt.wordCount)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWordCount(%d) error = %v, wantErr %v", tt.wordCount, err, tt.wantErr)
			}
		})
	}
}

func TestFalconHandler_GenerateMnemonic(t *testing.T) {
	h := &FalconHandler{}

	words, seed, entropy, err := h.GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic() error = %v", err)
	}

	// Check mnemonic has 24 words
	wordList := strings.Fields(words)
	if len(wordList) != 24 {
		t.Errorf("GenerateMnemonic() word count = %d, want 24", len(wordList))
	}

	// Check seed is not empty (64 bytes for BIP-39)
	if len(seed) == 0 {
		t.Error("GenerateMnemonic() seed should not be empty")
	}

	// Check entropy is 32 bytes (256 bits)
	if len(entropy) != 32 {
		t.Errorf("GenerateMnemonic() entropy length = %d, want 32", len(entropy))
	}
}

func TestFalconHandler_GenerateMnemonic_Unique(t *testing.T) {
	h := &FalconHandler{}

	words1, _, _, err1 := h.GenerateMnemonic()
	if err1 != nil {
		t.Fatalf("First GenerateMnemonic() error = %v", err1)
	}

	words2, _, _, err2 := h.GenerateMnemonic()
	if err2 != nil {
		t.Fatalf("Second GenerateMnemonic() error = %v", err2)
	}

	if words1 == words2 {
		t.Error("GenerateMnemonic() should produce different mnemonics each time")
	}
}

func TestFalconHandler_SeedFromMnemonic(t *testing.T) {
	h := &FalconHandler{}

	// Valid BIP-39 test mnemonic (24 words)
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	words := strings.Fields(testMnemonic)

	seed, err := h.SeedFromMnemonic(words, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic() error = %v", err)
	}

	if len(seed) == 0 {
		t.Error("SeedFromMnemonic() should return non-empty seed")
	}

	// Verify determinism - same mnemonic produces same seed
	seed2, _ := h.SeedFromMnemonic(words, "")
	if string(seed) != string(seed2) {
		t.Error("SeedFromMnemonic() should be deterministic")
	}
}

func TestFalconHandler_SeedFromMnemonic_WithPassphrase(t *testing.T) {
	h := &FalconHandler{}

	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	words := strings.Fields(testMnemonic)

	seed1, _ := h.SeedFromMnemonic(words, "")
	seed2, _ := h.SeedFromMnemonic(words, "my passphrase")

	if string(seed1) == string(seed2) {
		t.Error("SeedFromMnemonic() with different passphrases should produce different seeds")
	}
}

func TestFalconHandler_SeedFromMnemonic_Invalid(t *testing.T) {
	h := &FalconHandler{}

	tests := []struct {
		name  string
		words []string
	}{
		{"invalid words", []string{"invalid", "words", "not", "in", "dictionary"}},
		{"empty words", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.SeedFromMnemonic(tt.words, "")
			if err == nil {
				t.Error("SeedFromMnemonic() expected error for invalid mnemonic")
			}
		})
	}
}

func TestFalconHandler_EntropyToMnemonic(t *testing.T) {
	h := &FalconHandler{}

	// Test with 256 bits (32 bytes) of entropy
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	mnemonic, err := h.EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatalf("EntropyToMnemonic() error = %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		t.Errorf("EntropyToMnemonic() word count = %d, want 24", len(words))
	}
}

func TestFalconHandler_EntropyToMnemonic_Deterministic(t *testing.T) {
	h := &FalconHandler{}

	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	mnemonic1, _ := h.EntropyToMnemonic(entropy)
	mnemonic2, _ := h.EntropyToMnemonic(entropy)

	if mnemonic1 != mnemonic2 {
		t.Error("EntropyToMnemonic() should be deterministic")
	}
}
