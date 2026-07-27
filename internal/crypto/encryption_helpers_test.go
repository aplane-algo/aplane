// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewGCM_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}
	if gcm.NonceSize() != 12 {
		t.Errorf("NonceSize = %d, want 12", gcm.NonceSize())
	}
}

func TestNewGCM_InvalidKeyLength(t *testing.T) {
	for _, size := range []int{0, 15, 17, 31, 33} {
		_, err := newGCM(make([]byte, size))
		if err == nil {
			t.Errorf("newGCM(key len %d) should fail", size)
		}
	}
}

func TestSealWithRandomNonce_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}

	plaintext := []byte("round-trip test data")
	nonce, ciphertext, err := sealWithRandomNonce(gcm, plaintext)
	if err != nil {
		t.Fatalf("sealWithRandomNonce: %v", err)
	}

	if len(nonce) != gcm.NonceSize() {
		t.Errorf("nonce length = %d, want %d", len(nonce), gcm.NonceSize())
	}

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("gcm.Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestSealWithRandomNonce_UniqueNonces(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}

	nonce1, _, err := sealWithRandomNonce(gcm, []byte("a"))
	if err != nil {
		t.Fatalf("first seal: %v", err)
	}
	nonce2, _, err := sealWithRandomNonce(gcm, []byte("a"))
	if err != nil {
		t.Fatalf("second seal: %v", err)
	}

	if bytes.Equal(nonce1, nonce2) {
		t.Error("two calls should produce different nonces")
	}
}

func TestSealWithRandomNonce_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}

	nonce, ciphertext, err := sealWithRandomNonce(gcm, []byte{})
	if err != nil {
		t.Fatalf("sealWithRandomNonce: %v", err)
	}

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("gcm.Open: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestCheckEnvelopeVersion_Match(t *testing.T) {
	data := []byte(`{"envelope_version":1}`)
	if err := checkEnvelopeVersion(data, 1, "test"); err != nil {
		t.Errorf("should pass for matching version: %v", err)
	}
}

func TestCheckEnvelopeVersion_Mismatch(t *testing.T) {
	data := []byte(`{"envelope_version":2}`)
	err := checkEnvelopeVersion(data, 1, "master key decryption")
	if err == nil {
		t.Fatal("should fail for mismatched version")
	}
	if !strings.Contains(err.Error(), "master key decryption") {
		t.Errorf("error should include context, got: %v", err)
	}
	if !strings.Contains(err.Error(), "expected 1") {
		t.Errorf("error should include expected version, got: %v", err)
	}
}

func TestCheckEnvelopeVersion_InvalidJSON(t *testing.T) {
	err := checkEnvelopeVersion([]byte("not json"), 1, "test")
	if err == nil {
		t.Fatal("should fail for invalid JSON")
	}
}

func TestBuildKeystoreMetadata_Fields(t *testing.T) {
	passphrase := []byte("test-passphrase")

	meta, masterKey, err := buildKeystoreMetadata(passphrase)
	if err != nil {
		t.Fatalf("buildKeystoreMetadata: %v", err)
	}
	defer ZeroBytes(masterKey)

	if meta.Version != CurrentKeystoreMetadataVersion {
		t.Errorf("Version = %d, want %d", meta.Version, CurrentKeystoreMetadataVersion)
	}
	if meta.KDFTime != argon2Time {
		t.Errorf("KDFTime = %d, want %d", meta.KDFTime, argon2Time)
	}
	if meta.KDFMemory != argon2Memory {
		t.Errorf("KDFMemory = %d, want %d", meta.KDFMemory, argon2Memory)
	}
	if meta.KDFThreads != argon2Threads {
		t.Errorf("KDFThreads = %d, want %d", meta.KDFThreads, argon2Threads)
	}
	if meta.Salt == "" {
		t.Error("Salt should not be empty")
	}
	if meta.Check == "" {
		t.Error("Check should not be empty")
	}
	checkData, err := base64.StdEncoding.DecodeString(meta.Check)
	if err != nil {
		t.Fatalf("decode check value: %v", err)
	}
	checkPlain, err := decryptCheckValue(checkData, masterKey)
	if err != nil {
		t.Fatalf("decrypt check value: %v", err)
	}
	if string(checkPlain) != checkPlaintext {
		t.Errorf("check plaintext = %q, want %q", string(checkPlain), checkPlaintext)
	}
	if meta.Created == "" {
		t.Error("Created should not be empty")
	}
	if len(masterKey) != 32 {
		t.Errorf("master key length = %d, want 32", len(masterKey))
	}
}

func TestBuildKeystoreMetadata_Verifiable(t *testing.T) {
	passphrase := []byte("verify-me")

	meta, masterKey, err := buildKeystoreMetadata(passphrase)
	if err != nil {
		t.Fatalf("buildKeystoreMetadata: %v", err)
	}
	defer ZeroBytes(masterKey)

	// The returned metadata should be verifiable with the same passphrase
	derivedKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey: %v", err)
	}
	defer ZeroBytes(derivedKey)

	if !bytes.Equal(masterKey, derivedKey) {
		t.Error("derived key should match original master key")
	}
}

func TestBuildKeystoreMetadata_UniqueSalts(t *testing.T) {
	passphrase := []byte("same-passphrase")

	meta1, key1, err := buildKeystoreMetadata(passphrase)
	if err != nil {
		t.Fatalf("first buildKeystoreMetadata: %v", err)
	}
	defer ZeroBytes(key1)

	meta2, key2, err := buildKeystoreMetadata(passphrase)
	if err != nil {
		t.Fatalf("second buildKeystoreMetadata: %v", err)
	}
	defer ZeroBytes(key2)

	if meta1.Salt == meta2.Salt {
		t.Error("two calls should produce different salts")
	}
}
func TestVersion1KeystoreRejected(t *testing.T) {
	meta := &KeystoreMetadata{
		Version: 1,
		Salt:    base64Encode(make([]byte, masterSaltLen)),
		Check:   base64Encode([]byte("irrelevant")),
		Created: "2026-01-01T00:00:00Z",
	}
	if _, err := meta.VerifyAndDeriveMasterKey([]byte("any")); err == nil {
		t.Fatal("version-1 keystore accepted; this release reads only stores it initialized")
	}
}

func TestKeystoreMetadataRejectsLegacyCheckPlaintext(t *testing.T) {
	passphrase := []byte("legacy-check-passphrase")
	salt := make([]byte, masterSaltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	masterKey := DeriveMasterKey(passphrase, salt)
	defer ZeroBytes(masterKey)
	checkCiphertext := encryptTestCheckPlaintext(t, masterKey, "ALGOPLANE_OK")
	meta := &KeystoreMetadata{
		Version:    CurrentKeystoreMetadataVersion,
		Layout:     KeystoreLayoutGenerationsV1,
		Salt:       base64Encode(salt),
		Check:      base64Encode(checkCiphertext),
		Created:    "2026-01-01T00:00:00Z",
		KDFTime:    argon2Time,
		KDFMemory:  argon2Memory,
		KDFThreads: argon2Threads,
	}
	if _, err := meta.VerifyAndDeriveMasterKey(passphrase); err == nil {
		t.Fatal("legacy check plaintext accepted; the compatibility shim is removed")
	}
}

func encryptTestCheckPlaintext(t *testing.T, masterKey []byte, plaintext string) []byte {
	t.Helper()

	gcm, err := newGCM(masterKey)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}
	nonce, ciphertext, err := sealWithRandomNonce(gcm, []byte(plaintext))
	if err != nil {
		t.Fatalf("seal check value: %v", err)
	}
	return append(nonce, ciphertext...)
}

// TestVersion2Keystore_UsesStoredParams verifies that a version 2 keystore
// uses the KDF parameters stored in the metadata, not the hardcoded defaults.
func TestKeystoreUsesStoredParams(t *testing.T) {
	passphrase := []byte("v2-passphrase")

	meta, masterKey, err := buildKeystoreMetadata(passphrase)
	if err != nil {
		t.Fatalf("buildKeystoreMetadata: %v", err)
	}
	defer ZeroBytes(masterKey)

	if meta.Version != CurrentKeystoreMetadataVersion {
		t.Fatalf("expected version %d, got %d", CurrentKeystoreMetadataVersion, meta.Version)
	}
	if meta.KDFTime == 0 || meta.KDFMemory == 0 || meta.KDFThreads == 0 {
		t.Fatal("version 2 metadata should have non-zero KDF params")
	}

	derivedKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey on v2 keystore failed: %v", err)
	}
	defer ZeroBytes(derivedKey)

	if !bytes.Equal(masterKey, derivedKey) {
		t.Error("derived key from v2 keystore should match original")
	}
}

func TestKeystoreRejectsMissingKDFParamsBeforeDerive(t *testing.T) {
	meta := &KeystoreMetadata{
		Version: CurrentKeystoreMetadataVersion,
		Layout:  KeystoreLayoutGenerationsV1,
		Salt:    "not-needed",
		Check:   "not-needed",
		Created: "2026-01-01T00:00:00Z",
	}

	_, err := meta.VerifyAndDeriveMasterKey([]byte("passphrase"))
	if err == nil {
		t.Fatal("VerifyAndDeriveMasterKey error = nil, want incomplete KDF parameters")
	}
	if !strings.Contains(err.Error(), "incomplete KDF parameters") {
		t.Fatalf("VerifyAndDeriveMasterKey error = %q, want incomplete KDF parameters", err)
	}
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
