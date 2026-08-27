// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

func TestDecryptStandaloneRejectsEnvelopeWithoutKDFParams(t *testing.T) {
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

	_, err = DecryptStandalone(legacy, passphrase)
	if err == nil || !strings.Contains(err.Error(), "do not match envelope version 2") {
		t.Fatalf("DecryptStandalone legacy envelope error = %v, want exact KDF tuple rejection", err)
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
	if !strings.Contains(err.Error(), "do not match envelope version 2") {
		t.Errorf("Expected exact KDF tuple error, got: %v", err)
	}
}

func TestDecryptStandaloneRejectsModifiedKDFParamsBeforeDerivation(t *testing.T) {
	encrypted, err := EncryptStandalone([]byte("data"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	var envelope EncryptedDataStandalone
	if err := json.Unmarshal(encrypted, &envelope); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	envelope.KDFMemory++
	modified, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	_, err = DecryptStandalone(modified, []byte("pass"))
	if err == nil || !strings.Contains(err.Error(), "do not match envelope version 2") {
		t.Fatalf("DecryptStandalone() error = %v, want exact KDF tuple rejection", err)
	}
}

func TestDecryptStandaloneRejectsOversizedEnvelope(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, MaxStandaloneEnvelopeBytes+1)
	_, err := DecryptStandalone(data, []byte("pass"))
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("DecryptStandalone() error = %v, want size rejection", err)
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

// TestDecryptWithTermKeyRejectsVersion2 verifies term decryption rejects the
// standalone export format.
func TestDecryptWithTermKeyRejectsVersion2(t *testing.T) {
	encrypted, err := EncryptStandalone([]byte("data"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}

	fakeKey := make([]byte, 32)
	_, err = decryptWithTermKey(encrypted, fakeKey, FirstTerm, envelopeTestContext)
	if err == nil {
		t.Fatal("decryptWithTermKey should reject envelope_version 2")
	}
	if !strings.Contains(err.Error(), "is not a term envelope") {
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

func TestDecryptWithTermKeyRejectsInvalidNonceLength(t *testing.T) {
	payload := encryptedDataTerm{
		EnvelopeVersion: TermEnvelopeVersion,
		Term:            FirstTerm,
		Nonce:           base64.StdEncoding.EncodeToString([]byte("short")),
		Ciphertext:      base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	_, err = decryptWithTermKey(data, bytes.Repeat([]byte{1}, 32), FirstTerm, envelopeTestContext)
	if err == nil {
		t.Fatal("decryptWithTermKey() error = nil, want invalid nonce length")
	}
	if !strings.Contains(err.Error(), "invalid nonce length") {
		t.Fatalf("decryptWithTermKey() error = %v, want invalid nonce length", err)
	}
}

func TestDecryptStandaloneRejectsInvalidNonceLength(t *testing.T) {
	payload := EncryptedDataStandalone{
		EnvelopeVersion: 2,
		Salt:            base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, masterSaltLen)),
		Nonce:           base64.StdEncoding.EncodeToString([]byte("short")),
		Ciphertext:      base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		KDFTime:         argon2Time,
		KDFMemory:       argon2Memory,
		KDFThreads:      argon2Threads,
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
