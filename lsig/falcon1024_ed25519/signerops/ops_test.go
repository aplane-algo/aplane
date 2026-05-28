// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"crypto/ed25519"
	"testing"

	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconhybrid "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519"
)

func TestGenerateKeypairSizesAndDeterminism(t *testing.T) {
	ops := New()
	seed := testSeed()

	pub1, priv1, err := ops.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	pub2, priv2, err := ops.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() second error = %v", err)
	}

	if len(pub1) != falconhybrid.PublicKeySize {
		t.Fatalf("public key len = %d, want %d", len(pub1), falconhybrid.PublicKeySize)
	}
	if len(priv1) != falconhybrid.PrivateKeySize {
		t.Fatalf("private key len = %d, want %d", len(priv1), falconhybrid.PrivateKeySize)
	}
	if string(pub1) != string(pub2) || string(priv1) != string(priv2) {
		t.Fatal("GenerateKeypair() is not deterministic for the same seed")
	}

	edPub := pub1[family.PublicKeySize:]
	if len(edPub) != ed25519.PublicKeySize {
		t.Fatalf("ed25519 public key len = %d, want %d", len(edPub), ed25519.PublicKeySize)
	}
}

func TestSignAndBuildSignatureArgs(t *testing.T) {
	ops := New()
	pub, priv, err := ops.GenerateKeypair(testSeed())
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	message := []byte("01234567890123456789012345678901")
	sig, err := ops.Sign(priv, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	args, err := falconhybrid.NewOps().BuildSignatureArgs(sig)
	if err != nil {
		t.Fatalf("BuildSignatureArgs() error = %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("signature args len = %d, want 2", len(args))
	}
	if len(args[0]) == 0 || len(args[0]) > family.MaxSignatureSize {
		t.Fatalf("falcon signature len = %d, want 1..%d", len(args[0]), family.MaxSignatureSize)
	}
	if len(args[1]) != ed25519.SignatureSize {
		t.Fatalf("ed25519 signature len = %d, want %d", len(args[1]), ed25519.SignatureSize)
	}

	edPub := pub[family.PublicKeySize:]
	if !ed25519.Verify(edPub, message, args[1]) {
		t.Fatal("ed25519 signature did not verify over the message")
	}
}

func testSeed() []byte {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}
