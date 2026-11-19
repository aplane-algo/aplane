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

// A 64-byte input is re-derived from its seed half: a mismatched public half
// must not become the account's public key.
func TestOpsGenerateKeypairDerivesFromSeedHalfOfPrivateKey(t *testing.T) {
	ops := New()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	want := ed25519.NewKeyFromSeed(seed)

	forged := append(append([]byte(nil), seed...), bytes.Repeat([]byte{0x99}, ed25519.PublicKeySize)...)
	gotPublic, gotPrivate, err := ops.GenerateKeypair(forged)
	if err != nil {
		t.Fatalf("GenerateKeypair(forged) error = %v", err)
	}
	if !bytes.Equal(gotPublic, want.Public().(ed25519.PublicKey)) {
		t.Fatalf("GenerateKeypair(forged) public key = %x, want the key derived from the seed half", gotPublic)
	}
	if !bytes.Equal(gotPrivate, want) {
		t.Fatalf("GenerateKeypair(forged) private key does not match the seed half")
	}
}

// The returned public key must not alias the private key, so zeroing the
// private key (as the caller does) leaves the public key intact.
func TestOpsGenerateKeypairPublicKeySurvivesZeroedPrivateKey(t *testing.T) {
	ops := New()
	seed := bytes.Repeat([]byte{0x24}, ed25519.SeedSize)
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	gotPublic, gotPrivate, err := ops.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair(seed) error = %v", err)
	}
	for i := range gotPrivate {
		gotPrivate[i] = 0
	}
	if !bytes.Equal(gotPublic, want) {
		t.Fatal("public key changed when the private key was zeroed")
	}
}
