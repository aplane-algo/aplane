// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
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
	if err == nil || !strings.Contains(err.Error(), "outside supported range") {
		t.Fatalf("DecryptStandalone legacy envelope error = %v, want out-of-range KDF rejection", err)
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
	if !strings.Contains(err.Error(), "kdf_threads 0 is not supported") {
		t.Errorf("Expected kdf_threads rejection error, got: %v", err)
	}
}

func TestDecryptStandaloneRejectsOutOfRangeKDFParamsBeforeDerivation(t *testing.T) {
	encrypted, err := EncryptStandalone([]byte("data"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	var base EncryptedDataStandalone
	if err := json.Unmarshal(encrypted, &base); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*EncryptedDataStandalone)
		wantErr string
	}{
		{"time zero", func(e *EncryptedDataStandalone) { e.KDFTime = 0 }, "kdf_time 0 is outside supported range"},
		{"time below floor", func(e *EncryptedDataStandalone) { e.KDFTime = argon2MinTime - 1 }, "kdf_time 1 is outside supported range"},
		{"time above ceiling", func(e *EncryptedDataStandalone) { e.KDFTime = argon2MaxTime + 1 }, "kdf_time 5 is outside supported range"},
		{"time max uint32", func(e *EncryptedDataStandalone) { e.KDFTime = math.MaxUint32 }, "kdf_time 4294967295 is outside supported range"},
		{"memory zero", func(e *EncryptedDataStandalone) { e.KDFMemory = 0 }, "kdf_memory 0 is outside supported range"},
		{"memory below floor", func(e *EncryptedDataStandalone) { e.KDFMemory = argon2MinMemory - 1 }, "kdf_memory 65535 is outside supported range"},
		{"memory above ceiling", func(e *EncryptedDataStandalone) { e.KDFMemory = argon2MaxMemory + 1 }, "kdf_memory 262145 is outside supported range"},
		{"memory max uint32", func(e *EncryptedDataStandalone) { e.KDFMemory = math.MaxUint32 }, "kdf_memory 4294967295 is outside supported range"},
		{"threads zero", func(e *EncryptedDataStandalone) { e.KDFThreads = 0 }, "kdf_threads 0 is not supported"},
		{"threads below fixed", func(e *EncryptedDataStandalone) { e.KDFThreads = argon2AcceptedThreads - 1 }, "kdf_threads 3 is not supported"},
		{"threads above fixed", func(e *EncryptedDataStandalone) { e.KDFThreads = argon2AcceptedThreads + 1 }, "kdf_threads 5 is not supported"},
		{"threads max uint8", func(e *EncryptedDataStandalone) { e.KDFThreads = math.MaxUint8 }, "kdf_threads 255 is not supported"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kdfDeriveHook = func(tm, mem uint32, thr uint8) {
				t.Fatalf("Argon2id ran with (%d, %d, %d) despite out-of-range KDF parameters", tm, mem, thr)
			}
			defer func() { kdfDeriveHook = nil }()

			candidate := base
			tc.mutate(&candidate)
			modified, err := json.Marshal(candidate)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			_, err = DecryptStandalone(modified, []byte("pass"))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("DecryptStandalone() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestReleaseKDFDefaults(t *testing.T) {
	const (
		wantTime    uint32 = 2
		wantMemory  uint32 = 65536
		wantThreads uint8  = 4
	)
	if argon2Time != wantTime || argon2Memory != wantMemory || argon2Threads != wantThreads {
		t.Fatalf("sealing defaults = (%d, %d, %d), want (%d, %d, %d); update docs/ARCH_CRYPTO.md and internal/backup/readme.go alongside any change",
			argon2Time, argon2Memory, argon2Threads, wantTime, wantMemory, wantThreads)
	}

	standalone, err := EncryptStandalone([]byte("data"), []byte("passphrase"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	var env EncryptedDataStandalone
	if err := json.Unmarshal(standalone, &env); err != nil {
		t.Fatalf("Unmarshal(standalone) error = %v", err)
	}
	if env.KDFTime != wantTime || env.KDFMemory != wantMemory || env.KDFThreads != wantThreads {
		t.Fatalf("EncryptStandalone KDF = (%d, %d, %d), want (%d, %d, %d); keep docs/ARCH_CRYPTO.md and internal/backup/readme.go in sync",
			env.KDFTime, env.KDFMemory, env.KDFThreads, wantTime, wantMemory, wantThreads)
	}

	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	encodedRoot, err := SealStoreRoot(kr, []byte("passphrase"), testStoreRootGenerationA)
	if err != nil {
		t.Fatalf("SealStoreRoot() error = %v", err)
	}
	root, err := parseStoreRoot(encodedRoot)
	if err != nil {
		t.Fatalf("parseStoreRoot() error = %v", err)
	}
	var kf keyringFile
	if err := json.Unmarshal(root.Keyring, &kf); err != nil {
		t.Fatalf("Unmarshal(keyring) error = %v", err)
	}
	if kf.KDFTime != wantTime || kf.KDFMemory != wantMemory || kf.KDFThreads != wantThreads {
		t.Fatalf("SealStoreRoot KDF = (%d, %d, %d), want (%d, %d, %d); keep docs/ARCH_CRYPTO.md in sync",
			kf.KDFTime, kf.KDFMemory, kf.KDFThreads, wantTime, wantMemory, wantThreads)
	}
}

func sealStandaloneWithKDFForTest(t *testing.T, plaintext, passphrase []byte, kdfTime, kdfMemory uint32, kdfThreads uint8) []byte {
	t.Helper()
	salt, err := randomBytes(masterSaltLen)
	if err != nil {
		t.Fatalf("randomBytes(salt) error = %v", err)
	}
	key := deriveMasterKeyParams(passphrase, salt, kdfTime, kdfMemory, kdfThreads)
	defer ZeroBytes(key)
	gcm, err := newGCM(key)
	if err != nil {
		t.Fatalf("newGCM() error = %v", err)
	}
	nonce, ciphertext, err := sealWithRandomNonce(gcm, plaintext, nil)
	if err != nil {
		t.Fatalf("sealWithRandomNonce() error = %v", err)
	}
	encoded, err := json.MarshalIndent(EncryptedDataStandalone{
		EnvelopeVersion: 2,
		Salt:            base64.StdEncoding.EncodeToString(salt),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		KDFTime:         kdfTime,
		KDFMemory:       kdfMemory,
		KDFThreads:      kdfThreads,
	}, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	return encoded
}

func TestDecryptStandaloneDerivesFromStoredInRangeKDFParams(t *testing.T) {
	passphrase := []byte("stored-params-passphrase")
	plaintext := []byte(`{"key_type":"ed25519","secret":"preserved"}`)

	// Exact ceiling bounds are covered without heavy allocations in
	// TestCheckKDFParamsBounds; here we exercise real derivation at the
	// literal historical floor (2, 65536, 4) and a non-default in-range tuple.
	cases := []struct {
		name    string
		time    uint32
		memory  uint32
		threads uint8
	}{
		{"literal floor", 2, 65536, 4},
		{"mid-range non-default", 3, 68 * 1024, 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sealed := sealStandaloneWithKDFForTest(t, plaintext, passphrase, tc.time, tc.memory, tc.threads)

			var gotTime, gotMemory uint32
			var gotThreads uint8
			calls := 0
			kdfDeriveHook = func(tm, mem uint32, thr uint8) {
				calls++
				gotTime, gotMemory, gotThreads = tm, mem, thr
			}
			defer func() { kdfDeriveHook = nil }()

			decrypted, err := DecryptStandalone(sealed, passphrase)
			if err != nil {
				t.Fatalf("DecryptStandalone() error = %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("DecryptStandalone() = %q, want %q", decrypted, plaintext)
			}
			if calls != 1 || gotTime != tc.time || gotMemory != tc.memory || gotThreads != tc.threads {
				t.Fatalf("derived with (%d, %d, %d) x%d, want (%d, %d, %d) x1",
					gotTime, gotMemory, gotThreads, calls, tc.time, tc.memory, tc.threads)
			}
		})
	}

	// Editing an in-range KDF parameter after sealing changes the derived key
	// and must fail AES-GCM authentication.
	sealed, err := EncryptStandalone(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	var envelope EncryptedDataStandalone
	if err := json.Unmarshal(sealed, &envelope); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	envelope.KDFMemory++
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var gotMemory uint32
	kdfDeriveHook = func(_, mem uint32, _ uint8) { gotMemory = mem }
	defer func() { kdfDeriveHook = nil }()
	if _, err := DecryptStandalone(tampered, passphrase); err == nil || !strings.Contains(err.Error(), "failed to decrypt data") {
		t.Fatalf("DecryptStandalone(in-range tampered KDF) error = %v, want decrypt failure", err)
	}
	if gotMemory != argon2Memory+1 {
		t.Fatalf("derived memory = %d, want %d", gotMemory, argon2Memory+1)
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

// TestKeyringOpenRejectsVersion2 verifies term decryption rejects the
// standalone export format.
func TestKeyringOpenRejectsVersion2(t *testing.T) {
	encrypted, err := EncryptStandalone([]byte("data"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptStandalone failed: %v", err)
	}

	fakeKey := make([]byte, 32)
	_, err = termKeyring(t, fakeKey).Open(encrypted, envelopeTestContext)
	if err == nil {
		t.Fatal("Keyring.Open should reject envelope_version 2")
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

func TestKeyringOpenRejectsInvalidNonceLength(t *testing.T) {
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

	_, err = termKeyring(t, bytes.Repeat([]byte{1}, 32)).Open(data, envelopeTestContext)
	if err == nil {
		t.Fatal("Keyring.Open() error = nil, want invalid nonce length")
	}
	if !strings.Contains(err.Error(), "invalid nonce length") {
		t.Fatalf("Keyring.Open() error = %v, want invalid nonce length", err)
	}
}

func TestDecryptStandaloneRejectsInvalidNonceLength(t *testing.T) {
	cases := []struct {
		name  string
		nonce []byte
	}{
		{"short", bytes.Repeat([]byte{1}, gcmNonceBytes-1)},
		{"long", bytes.Repeat([]byte{1}, gcmNonceBytes+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := EncryptedDataStandalone{
				EnvelopeVersion: 2,
				Salt:            base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, masterSaltLen)),
				Nonce:           base64.StdEncoding.EncodeToString(tc.nonce),
				Ciphertext:      base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, gcmTagBytes)),
				KDFTime:         argon2MinTime,
				KDFMemory:       argon2MinMemory,
				KDFThreads:      argon2AcceptedThreads,
			}
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			kdfDeriveHook = func(tm, mem uint32, thr uint8) {
				t.Fatalf("Argon2id ran with (%d, %d, %d) despite invalid nonce length", tm, mem, thr)
			}
			defer func() { kdfDeriveHook = nil }()

			_, err = DecryptStandalone(data, []byte("passphrase"))
			if err == nil || !strings.Contains(err.Error(), "invalid nonce length") {
				t.Fatalf("DecryptStandalone() error = %v, want invalid nonce length", err)
			}
		})
	}
}

func TestDecryptStandaloneRejectsShortCiphertextBeforeDerivation(t *testing.T) {
	payload := EncryptedDataStandalone{
		EnvelopeVersion: 2,
		Salt:            base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, masterSaltLen)),
		Nonce:           base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, gcmNonceBytes)),
		Ciphertext:      base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, gcmTagBytes-1)),
		KDFTime:         argon2MinTime,
		KDFMemory:       argon2MinMemory,
		KDFThreads:      argon2AcceptedThreads,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	kdfDeriveHook = func(tm, mem uint32, thr uint8) {
		t.Fatalf("Argon2id ran with (%d, %d, %d) despite short ciphertext", tm, mem, thr)
	}
	defer func() { kdfDeriveHook = nil }()

	_, err = DecryptStandalone(data, []byte("passphrase"))
	if err == nil || !strings.Contains(err.Error(), "ciphertext is too short") {
		t.Fatalf("DecryptStandalone() error = %v, want short ciphertext rejection", err)
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
