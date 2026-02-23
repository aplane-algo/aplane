// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package crypto

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMasterKeyEncryptDecrypt_RoundTrip tests master key encrypt/decrypt cycle
func TestMasterKeyEncryptDecrypt_RoundTrip(t *testing.T) {
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
			encrypted, err := EncryptWithMasterKey(tt.plaintext, masterKey)
			if err != nil {
				t.Fatalf("EncryptWithMasterKey failed: %v", err)
			}

			// Decrypt with master key
			decrypted, err := DecryptWithMasterKey(encrypted, masterKey)
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
func TestMasterKeyEncrypt_Randomness(t *testing.T) {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	defer ZeroBytes(masterKey)

	plaintext := []byte("test data")

	encrypted1, err := EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey 1 failed: %v", err)
	}

	encrypted2, err := EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey 2 failed: %v", err)
	}

	// The encrypted outputs should be different (different nonce each time)
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("Encrypting same data twice should produce different ciphertexts due to random nonce")
	}

	// But both should decrypt to the same plaintext
	decrypted1, _ := DecryptWithMasterKey(encrypted1, masterKey)
	decrypted2, _ := DecryptWithMasterKey(encrypted2, masterKey)
	defer ZeroBytes(decrypted1)
	defer ZeroBytes(decrypted2)

	if !bytes.Equal(decrypted1, decrypted2) {
		t.Error("Both encryptions should decrypt to the same plaintext")
	}
}

// TestMasterKeyDecrypt_WrongKey verifies wrong key is rejected
func TestMasterKeyDecrypt_WrongKey(t *testing.T) {
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

	encrypted, err := EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = DecryptWithMasterKey(encrypted, wrongKey)
	if err == nil {
		t.Fatal("DecryptWithMasterKey should fail with wrong key")
	}
}

// TestVerifyPassphraseWithMetadata_Correct verifies correct passphrase is accepted
func TestVerifyPassphraseWithMetadata_Correct(t *testing.T) {
	tmpDir := t.TempDir()
	keystoreDir := filepath.Join(tmpDir, "keystore")
	if err := os.Mkdir(keystoreDir, 0750); err != nil {
		t.Fatalf("Failed to create keystore dir: %v", err)
	}

	passphrase := []byte("correct-passphrase")

	// Create keystore metadata
	_, masterKey, err := CreateKeystoreMetadata(keystoreDir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata failed: %v", err)
	}
	defer ZeroBytes(masterKey)

	// Verify with correct passphrase - should succeed
	err = VerifyPassphraseWithMetadata(passphrase, keystoreDir)
	if err != nil {
		t.Errorf("VerifyPassphraseWithMetadata should succeed with correct passphrase: %v", err)
	}
}

// TestVerifyPassphraseWithMetadata_Incorrect verifies wrong passphrase is rejected
func TestVerifyPassphraseWithMetadata_Incorrect(t *testing.T) {
	tmpDir := t.TempDir()
	keystoreDir := filepath.Join(tmpDir, "keystore")
	if err := os.Mkdir(keystoreDir, 0750); err != nil {
		t.Fatalf("Failed to create keystore dir: %v", err)
	}

	correctPass := []byte("correct-passphrase")
	wrongPass := []byte("wrong-passphrase")

	// Create keystore metadata with correct passphrase
	_, masterKey, err := CreateKeystoreMetadata(keystoreDir, correctPass)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata failed: %v", err)
	}
	defer ZeroBytes(masterKey)

	// Verify with wrong passphrase - should fail
	err = VerifyPassphraseWithMetadata(wrongPass, keystoreDir)
	if err == nil {
		t.Error("VerifyPassphraseWithMetadata should fail with wrong passphrase")
	}

	if !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Errorf("Error should mention incorrect passphrase, got: %v", err)
	}
}

// TestVerifyPassphraseWithMetadata_NoMetadata verifies error when metadata missing
func TestVerifyPassphraseWithMetadata_NoMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	keystoreDir := filepath.Join(tmpDir, "keystore")
	if err := os.Mkdir(keystoreDir, 0750); err != nil {
		t.Fatalf("Failed to create keystore dir: %v", err)
	}

	err := VerifyPassphraseWithMetadata([]byte("any-passphrase"), keystoreDir)
	if err == nil {
		t.Error("VerifyPassphraseWithMetadata should fail when metadata doesn't exist")
	}

	if !strings.Contains(err.Error(), "not initialized") && !strings.Contains(err.Error(), "missing") {
		t.Errorf("Error should mention keystore not initialized, got: %v", err)
	}
}

// TestCreateKeystoreMetadata_CreatesDir verifies function creates dir if needed
func TestCreateKeystoreMetadata_CreatesDir(t *testing.T) {
	tmpDir := t.TempDir()
	// Keystore dir doesn't exist yet
	keystoreDir := filepath.Join(tmpDir, "keystore")

	passphrase := []byte("test-passphrase")

	_, masterKey, err := CreateKeystoreMetadata(keystoreDir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata should create dir: %v", err)
	}
	defer ZeroBytes(masterKey)

	// Verify keystore dir was created
	info, err := os.Stat(keystoreDir)
	if err != nil {
		t.Fatalf("keystore directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("keystore should be a directory")
	}

	// Verify .keystore file was created
	metaPath := filepath.Join(keystoreDir, ".keystore")
	_, err = os.Stat(metaPath)
	if err != nil {
		t.Fatalf(".keystore file should exist: %v", err)
	}
}
