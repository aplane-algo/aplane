// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestOpsGenerateKeypairAcceptsSeedAndPrivateKey(t *testing.T) {
	ops := New()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	gotPublic, gotPrivate, err := ops.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair(seed) error = %v", err)
	}
	if !bytes.Equal(gotPublic, publicKey) {
		t.Fatalf("GenerateKeypair(seed) public key mismatch")
	}
	if !bytes.Equal(gotPrivate, privateKey) {
		t.Fatalf("GenerateKeypair(seed) private key mismatch")
	}

	gotPublic, gotPrivate, err = ops.GenerateKeypair(privateKey)
	if err != nil {
		t.Fatalf("GenerateKeypair(privateKey) error = %v", err)
	}
	if !bytes.Equal(gotPublic, publicKey) {
		t.Fatalf("GenerateKeypair(privateKey) public key mismatch")
	}
	if !bytes.Equal(gotPrivate, privateKey) {
		t.Fatalf("GenerateKeypair(privateKey) private key mismatch")
	}
}

func TestOpsGenerateKeypairRejectsInvalidSeedLength(t *testing.T) {
	ops := New()
	if _, _, err := ops.GenerateKeypair([]byte{0x01}); err == nil {
		t.Fatal("GenerateKeypair() accepted invalid seed length")
	}
}

func TestOpsSign(t *testing.T) {
	ops := New()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	message := []byte("message")

	signature, err := ops.Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), message, signature) {
		t.Fatal("signature did not verify")
	}
	if _, err := ops.Sign(privateKey[:63], message); err == nil {
		t.Fatal("Sign() accepted short private key")
	}
}
