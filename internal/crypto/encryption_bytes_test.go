// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestMasterKeyEncryptDecrypt_RoundTrip tests master key encrypt/decrypt cycle
// envelopeTestContext is the object identity these envelope tests seal and
// open under. Which object it names does not matter here; that both sides
// name the same one does.
var envelopeTestContext = AccountKeyContext("ENVELOPETESTADDRESS")

func TestTermEnvelopeEncryptDecrypt_RoundTrip(t *testing.T) {
	// Create a master key (32 bytes)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	defer ZeroBytes(masterKey)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "empty plaintext",
			plaintext: []byte{},
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0xFF, 0xFE, 0x42, 0x00, 0x00, 0xFF},
		},
		{
			name:      "large data",
			plaintext: bytes.Repeat([]byte("X"), 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt with master key
			encrypted, err := EncryptWithTermKey(tt.plaintext, masterKey, FirstTerm, envelopeTestContext)
			if err != nil {
				t.Fatalf("EncryptWithMasterKey failed: %v", err)
			}

			// Decrypt with master key
			decrypted, err := DecryptWithTermKey(encrypted, masterKey, FirstTerm, envelopeTestContext)
			if err != nil {
				t.Fatalf("DecryptWithMasterKey failed: %v", err)
			}
			defer ZeroBytes(decrypted)

			// Verify plaintext matches
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypted data doesn't match original.\nExpected: %v\nGot: %v", tt.plaintext, decrypted)
			}
		})
	}
}

// TestMasterKeyEncrypt_Randomness verifies each encryption uses different nonce
func TestTermEnvelopeEncrypt_Randomness(t *testing.T) {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	defer ZeroBytes(masterKey)

	plaintext := []byte("test data")

	encrypted1, err := EncryptWithTermKey(plaintext, masterKey, FirstTerm, envelopeTestContext)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey 1 failed: %v", err)
	}

	encrypted2, err := EncryptWithTermKey(plaintext, masterKey, FirstTerm, envelopeTestContext)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey 2 failed: %v", err)
	}

	// The encrypted outputs should be different (different nonce each time)
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("Encrypting same data twice should produce different ciphertexts due to random nonce")
	}

	// But both should decrypt to the same plaintext
	decrypted1, _ := DecryptWithTermKey(encrypted1, masterKey, FirstTerm, envelopeTestContext)
	decrypted2, _ := DecryptWithTermKey(encrypted2, masterKey, FirstTerm, envelopeTestContext)
	defer ZeroBytes(decrypted1)
	defer ZeroBytes(decrypted2)

	if !bytes.Equal(decrypted1, decrypted2) {
		t.Error("Both encryptions should decrypt to the same plaintext")
	}
}

// TestMasterKeyDecrypt_WrongKey verifies wrong key is rejected
func TestTermEnvelopeDecrypt_WrongKey(t *testing.T) {
	masterKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}
	defer ZeroBytes(masterKey)
	defer ZeroBytes(wrongKey)

	plaintext := []byte("secret data")

	encrypted, err := EncryptWithTermKey(plaintext, masterKey, FirstTerm, envelopeTestContext)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = DecryptWithTermKey(encrypted, wrongKey, FirstTerm, envelopeTestContext)
	if err == nil {
		t.Fatal("DecryptWithMasterKey should fail with wrong key")
	}
}
