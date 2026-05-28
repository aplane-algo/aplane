// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsEncrypted verifies detection of encrypted vs plaintext data
func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "encrypted data",
			data:     []byte(`{"envelope_version":1,"salt":"abc","nonce":"def","ciphertext":"ghi"}`),
			expected: true,
		},
		{
			name:     "plaintext",
			data:     []byte("This is plaintext"),
			expected: false,
		},
		{
			name:     "empty data",
			data:     []byte(""),
			expected: false,
		},
		{
			name:     "invalid JSON",
			data:     []byte("{invalid json"),
			expected: false,
		},
		{
			name:     "JSON without version",
			data:     []byte(`{"salt":"abc"}`),
			expected: false,
		},
		{
			name:     "JSON with version 0",
			data:     []byte(`{"envelope_version":0,"salt":"abc"}`),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEncrypted(tt.data)
			if result != tt.expected {
				t.Errorf("IsEncrypted(%q) = %v, expected %v", tt.data, result, tt.expected)
			}
		})
	}
}

// TestKeystoreMetadataWorkflow verifies keystore metadata creation and verification
func TestKeystoreMetadataWorkflow(t *testing.T) {
	// Create temporary keystore directory
	tmpDir := t.TempDir()
	keystoreDir := filepath.Join(tmpDir, "keystore")
	if err := os.Mkdir(keystoreDir, 0750); err != nil {
		t.Fatalf("Failed to create keystore dir: %v", err)
	}

	passphrase := []byte("test-keystore-passphrase")

	// Verify metadata file doesn't exist initially
	if KeystoreMetadataExistsIn(keystoreDir) {
		t.Error("Keystore metadata should not exist initially")
	}

	// Create keystore metadata
	meta, masterKey, err := CreateKeystoreMetadata(keystoreDir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata failed: %v", err)
	}
	defer ZeroBytes(masterKey)

	// Verify it exists now
	if !KeystoreMetadataExistsIn(keystoreDir) {
		t.Error("Keystore metadata should exist after creation")
	}

	// Verify metadata structure
	if meta.Version != 2 {
		t.Errorf("Expected version 2, got %d", meta.Version)
	}
	if meta.Salt == "" {
		t.Error("Salt should not be empty")
	}
	if meta.Check == "" {
		t.Error("Check should not be empty")
	}
	if meta.Created == "" {
		t.Error("Created timestamp should not be empty")
	}

	// Verify correct passphrase returns master key
	derivedKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Errorf("VerifyAndDeriveMasterKey failed with correct passphrase: %v", err)
	}
	defer ZeroBytes(derivedKey)

	// Verify derived key matches original
	if !bytes.Equal(masterKey, derivedKey) {
		t.Error("Derived master key should match original")
	}

	// Verify wrong passphrase is rejected
	wrongPass := []byte("wrong-passphrase")
	_, err = meta.VerifyAndDeriveMasterKey(wrongPass)
	if err == nil {
		t.Error("VerifyAndDeriveMasterKey should fail with wrong passphrase")
	}
	if !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Errorf("Error should mention incorrect passphrase, got: %v", err)
	}
}

func TestLoadKeystoreMetadataRejectsUnsupportedVersion(t *testing.T) {
	passphrase := []byte("test-keystore-passphrase")
	keystoreDir := t.TempDir()
	meta, masterKey, err := CreateKeystoreMetadata(keystoreDir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata failed: %v", err)
	}
	defer ZeroBytes(masterKey)

	for _, tt := range []struct {
		name    string
		version int
	}{
		{name: "missing", version: 0},
		{name: "future", version: CurrentKeystoreMetadataVersion + 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			candidate := *meta
			candidate.Version = tt.version
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatalf("Marshal metadata failed: %v", err)
			}
			metaPath := filepath.Join(t.TempDir(), ".keystore")
			if err := os.WriteFile(metaPath, data, 0600); err != nil {
				t.Fatalf("WriteFile metadata failed: %v", err)
			}

			_, err = LoadKeystoreMetadataFrom(metaPath)
			if err == nil || !strings.Contains(err.Error(), "unsupported keystore metadata version") {
				t.Fatalf("LoadKeystoreMetadataFrom() error = %v, want unsupported version", err)
			}
		})
	}
}

func TestLoadKeystoreMetadataRejectsVersion2IncompleteKDFParams(t *testing.T) {
	passphrase := []byte("test-keystore-passphrase")
	keystoreDir := t.TempDir()
	meta, masterKey, err := CreateKeystoreMetadata(keystoreDir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata failed: %v", err)
	}
	defer ZeroBytes(masterKey)

	tests := []struct {
		name string
		edit func(*KeystoreMetadata)
	}{
		{
			name: "missing all",
			edit: func(m *KeystoreMetadata) {
				m.KDFTime = 0
				m.KDFMemory = 0
				m.KDFThreads = 0
			},
		},
		{
			name: "missing time",
			edit: func(m *KeystoreMetadata) {
				m.KDFTime = 0
			},
		},
		{
			name: "missing memory",
			edit: func(m *KeystoreMetadata) {
				m.KDFMemory = 0
			},
		},
		{
			name: "missing threads",
			edit: func(m *KeystoreMetadata) {
				m.KDFThreads = 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := *meta
			tt.edit(&candidate)
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatalf("Marshal metadata failed: %v", err)
			}
			metaPath := filepath.Join(t.TempDir(), ".keystore")
			if err := os.WriteFile(metaPath, data, 0o600); err != nil {
				t.Fatalf("WriteFile metadata failed: %v", err)
			}

			_, err = LoadKeystoreMetadataFrom(metaPath)
			if err == nil || !strings.Contains(err.Error(), "incomplete KDF parameters") {
				t.Fatalf("LoadKeystoreMetadataFrom() error = %v, want incomplete KDF parameters", err)
			}
		})
	}
}

// TestStandaloneEncryptionRoundTrip verifies encrypt/decrypt cycle for standalone format
func TestStandaloneEncryptionRoundTrip(t *testing.T) {
	passphrase := []byte("test-standalone-passphrase")
	plaintext := []byte(`{"key_type":"ed25519","public_key":"abc123","private_key":"def456"}`)

	encrypted, err := EncryptStandalone(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}

	decrypted, err := DecryptStandalone(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptStandalone failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestStandaloneEncryptionWrongPassphrase verifies decryption fails with wrong passphrase
func TestStandaloneEncryptionWrongPassphrase(t *testing.T) {
	passphrase := []byte("correct-passphrase")
	wrong := []byte("wrong-passphrase")
	plaintext := []byte("secret data")

	encrypted, err := EncryptStandalone(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}

	_, err = DecryptStandalone(encrypted, wrong)
	if err == nil {
		t.Fatal("DecryptStandalone should fail with wrong passphrase")
	}
	if !strings.Contains(err.Error(), "failed to decrypt") {
		t.Errorf("Expected decrypt failure error, got: %v", err)
	}
}

// TestStandaloneEncryptionEnvelopeVersion verifies the output has envelope_version 2
func TestStandaloneEncryptionEnvelopeVersion(t *testing.T) {
	encrypted, err := EncryptStandalone([]byte("data"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}

	var envelope struct {
		EnvelopeVersion int    `json:"envelope_version"`
		Salt            string `json:"salt"`
		Nonce           string `json:"nonce"`
		Ciphertext      string `json:"ciphertext"`
		KDFTime         uint32 `json:"kdf_time"`
		KDFMemory       uint32 `json:"kdf_memory"`
		KDFThreads      uint8  `json:"kdf_threads"`
	}
	if err := json.Unmarshal(encrypted, &envelope); err != nil {
		t.Fatalf("Failed to parse encrypted output: %v", err)
	}

	if envelope.EnvelopeVersion != 2 {
		t.Errorf("Expected envelope_version 2, got %d", envelope.EnvelopeVersion)
	}
	if envelope.Salt == "" {
		t.Error("Salt should not be empty")
	}
	if envelope.Nonce == "" {
		t.Error("Nonce should not be empty")
	}
	if envelope.Ciphertext == "" {
		t.Error("Ciphertext should not be empty")
	}
	if envelope.KDFTime != argon2Time {
		t.Errorf("KDFTime = %d, want %d", envelope.KDFTime, argon2Time)
	}
	if envelope.KDFMemory != argon2Memory {
		t.Errorf("KDFMemory = %d, want %d", envelope.KDFMemory, argon2Memory)
	}
	if envelope.KDFThreads != argon2Threads {
		t.Errorf("KDFThreads = %d, want %d", envelope.KDFThreads, argon2Threads)
	}
}

func TestDecryptStandaloneAcceptsLegacyEnvelopeWithoutKDFParams(t *testing.T) {
	passphrase := []byte("test-standalone-passphrase")
	plaintext := []byte("legacy standalone envelope")

	encrypted, err := EncryptStandalone(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(encrypted, &envelope); err != nil {
		t.Fatalf("Failed to parse encrypted output: %v", err)
	}
	delete(envelope, "kdf_time")
	delete(envelope, "kdf_memory")
	delete(envelope, "kdf_threads")
	legacy, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Failed to marshal legacy envelope: %v", err)
	}

	decrypted, err := DecryptStandalone(legacy, passphrase)
	if err != nil {
		t.Fatalf("DecryptStandalone legacy envelope failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("DecryptStandalone legacy plaintext = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptStandaloneRejectsIncompleteKDFParams(t *testing.T) {
	encrypted, err := EncryptStandalone([]byte("data"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(encrypted, &envelope); err != nil {
		t.Fatalf("Failed to parse encrypted output: %v", err)
	}
	delete(envelope, "kdf_threads")
	partial, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Failed to marshal partial envelope: %v", err)
	}

	_, err = DecryptStandalone(partial, []byte("pass"))
	if err == nil {
		t.Fatal("DecryptStandalone should reject incomplete KDF parameters")
	}
	if !strings.Contains(err.Error(), "incomplete KDF parameters") {
		t.Errorf("Expected incomplete KDF error, got: %v", err)
	}
}

// TestIsEncryptedVersion2 verifies IsEncrypted detects version 2 envelopes
func TestIsEncryptedVersion2(t *testing.T) {
	encrypted, err := EncryptStandalone([]byte("data"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}

	if !IsEncrypted(encrypted) {
		t.Error("IsEncrypted should return true for envelope_version 2")
	}
}

// TestDecryptWithMasterKeyRejectsVersion2 verifies master key decryption rejects standalone format
func TestDecryptWithMasterKeyRejectsVersion2(t *testing.T) {
	encrypted, err := EncryptStandalone([]byte("data"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}

	fakeKey := make([]byte, 32)
	_, err = DecryptWithMasterKey(encrypted, fakeKey)
	if err == nil {
		t.Fatal("DecryptWithMasterKey should reject envelope_version 2")
	}
	if !strings.Contains(err.Error(), "not supported by master key decryption") {
		t.Errorf("Expected version mismatch error, got: %v", err)
	}
}

// TestDecryptStandaloneRejectsVersion1 verifies standalone decryption rejects master key format
func TestDecryptStandaloneRejectsVersion1(t *testing.T) {
	v1Data := []byte(`{"envelope_version":1,"nonce":"abc","ciphertext":"def"}`)

	_, err := DecryptStandalone(v1Data, []byte("pass"))
	if err == nil {
		t.Fatal("DecryptStandalone should reject envelope_version 1")
	}
	if !strings.Contains(err.Error(), "not supported by standalone decryption") {
		t.Errorf("Expected version mismatch error, got: %v", err)
	}
}

func TestDecryptWithMasterKeyRejectsInvalidNonceLength(t *testing.T) {
	payload := EncryptedDataMasterKey{
		EnvelopeVersion: 1,
		Nonce:           base64.StdEncoding.EncodeToString([]byte("short")),
		Ciphertext:      base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	_, err = DecryptWithMasterKey(data, bytes.Repeat([]byte{1}, 32))
	if err == nil {
		t.Fatal("DecryptWithMasterKey() error = nil, want invalid nonce length")
	}
	if !strings.Contains(err.Error(), "invalid nonce length") {
		t.Fatalf("DecryptWithMasterKey() error = %v, want invalid nonce length", err)
	}
}

func TestDecryptStandaloneRejectsInvalidNonceLength(t *testing.T) {
	payload := EncryptedDataStandalone{
		EnvelopeVersion: 2,
		Salt:            base64.StdEncoding.EncodeToString([]byte("salt")),
		Nonce:           base64.StdEncoding.EncodeToString([]byte("short")),
		Ciphertext:      base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	_, err = DecryptStandalone(data, []byte("passphrase"))
	if err == nil {
		t.Fatal("DecryptStandalone() error = nil, want invalid nonce length")
	}
	if !strings.Contains(err.Error(), "invalid nonce length") {
		t.Fatalf("DecryptStandalone() error = %v, want invalid nonce length", err)
	}
}

// TestStandaloneEncryptionRandomness verifies each encryption produces different output
func TestStandaloneEncryptionRandomness(t *testing.T) {
	passphrase := []byte("test-pass")
	plaintext := []byte("same data")

	enc1, err := EncryptStandalone(plaintext, passphrase)
	if err != nil {
		t.Fatalf("First EncryptStandalone failed: %v", err)
	}

	enc2, err := EncryptStandalone(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Second EncryptStandalone failed: %v", err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Error("Two encryptions of the same data should produce different output (different salt/nonce)")
	}

	// Both should still decrypt to the same plaintext
	dec1, err := DecryptStandalone(enc1, passphrase)
	if err != nil {
		t.Fatalf("First DecryptStandalone failed: %v", err)
	}
	dec2, err := DecryptStandalone(enc2, passphrase)
	if err != nil {
		t.Fatalf("Second DecryptStandalone failed: %v", err)
	}

	if !bytes.Equal(dec1, dec2) {
		t.Error("Both decryptions should produce the same plaintext")
	}
}
