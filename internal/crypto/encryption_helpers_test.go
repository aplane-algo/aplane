// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"crypto/rand"
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
