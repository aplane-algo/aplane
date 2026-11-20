// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"crypto/rand"
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
	nonce, ciphertext, err := sealWithRandomNonce(gcm, plaintext, nil)
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

	nonce1, _, err := sealWithRandomNonce(gcm, []byte("a"), nil)
	if err != nil {
		t.Fatalf("first seal: %v", err)
	}
	nonce2, _, err := sealWithRandomNonce(gcm, []byte("a"), nil)
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

	nonce, ciphertext, err := sealWithRandomNonce(gcm, []byte{}, nil)
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
