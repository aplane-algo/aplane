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
			encrypted, err := termKeyring(t, masterKey).Seal(tt.plaintext, envelopeTestContext)
			if err != nil {
				t.Fatalf("Keyring.Seal failed: %v", err)
			}

			// Decrypt with master key
			decrypted, err := termKeyring(t, masterKey).Open(encrypted, envelopeTestContext)
			if err != nil {
				t.Fatalf("Keyring.Open failed: %v", err)
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

	encrypted1, err := termKeyring(t, masterKey).Seal(plaintext, envelopeTestContext)
	if err != nil {
		t.Fatalf("Keyring.Seal 1 failed: %v", err)
	}

	encrypted2, err := termKeyring(t, masterKey).Seal(plaintext, envelopeTestContext)
	if err != nil {
		t.Fatalf("Keyring.Seal 2 failed: %v", err)
	}

	// The encrypted outputs should be different (different nonce each time)
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("Encrypting same data twice should produce different ciphertexts due to random nonce")
	}

	// But both should decrypt to the same plaintext
	decrypted1, _ := termKeyring(t, masterKey).Open(encrypted1, envelopeTestContext)
	decrypted2, _ := termKeyring(t, masterKey).Open(encrypted2, envelopeTestContext)
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

	encrypted, err := termKeyring(t, masterKey).Seal(plaintext, envelopeTestContext)
	if err != nil {
		t.Fatalf("Keyring.Seal failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = termKeyring(t, wrongKey).Open(encrypted, envelopeTestContext)
	if err == nil {
		t.Fatal("Keyring.Open should fail with wrong key")
	}
}

// termKeyring returns a one-term keyring holding key, so tests seal and open
// through the same path as production.
func termKeyring(t *testing.T, key []byte) *Keyring {
	t.Helper()
	kr, err := NewKeyringFromKey(key)
	if err != nil {
		t.Fatalf("NewKeyringFromKey(): %v", err)
	}
	return kr
}
