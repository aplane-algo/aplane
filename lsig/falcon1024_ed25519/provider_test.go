// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024ed25519

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestProviderV1Identity(t *testing.T) {
	p := NewProviderV1()

	if p.KeyType() != KeyTypeV1 {
		t.Fatalf("KeyType() = %q, want %q", p.KeyType(), KeyTypeV1)
	}
	if p.RoutingFamily() != FamilyName {
		t.Fatalf("RoutingFamily() = %q, want %q", p.RoutingFamily(), FamilyName)
	}
	if p.CryptoSignatureSize() != SignatureSize {
		t.Fatalf("CryptoSignatureSize() = %d, want %d", p.CryptoSignatureSize(), SignatureSize)
	}
	if p.CryptoSignatureSize() != family.MaxSignatureSize+ed25519.SignatureSize {
		t.Fatalf("CryptoSignatureSize() = %d, want falcon max + ed25519 signature", p.CryptoSignatureSize())
	}
}

func TestOpsBuildSignatureArgs(t *testing.T) {
	ops := NewOps()
	falconSig := []byte{1, 2, 3}
	edSig := make([]byte, ed25519.SignatureSize)
	sig := append([]byte{0, byte(len(falconSig))}, falconSig...)
	sig = append(sig, edSig...)

	args, err := ops.BuildSignatureArgs(sig)
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
}

func TestOpsBuildVerifyTEAL(t *testing.T) {
	ops := NewOps()
	pub := make([]byte, PublicKeySize)

	teal, err := ops.BuildVerifyTEAL(pub)
	if err != nil {
		t.Fatalf("BuildVerifyTEAL() error = %v", err)
	}

	for _, want := range []string{
		"txn TxID",
		"arg 0",
		"falcon_verify",
		"assert",
		"arg 1",
		"ed25519verify_bare",
	} {
		if !strings.Contains(teal, want) {
			t.Fatalf("BuildVerifyTEAL() missing %q:\n%s", want, teal)
		}
	}
	if strings.Index(teal, "falcon_verify") > strings.Index(teal, "ed25519verify_bare") {
		t.Fatalf("BuildVerifyTEAL() should verify Falcon before Ed25519:\n%s", teal)
	}
}

func TestRegisterClient(t *testing.T) {
	RegisterClient()

	if dsa := logicsigdsa.Get(KeyTypeV1); dsa == nil {
		t.Fatalf("logicsigdsa.Get(%q) = nil", KeyTypeV1)
	}
	if provider := lsigprovider.Get(KeyTypeV1); provider == nil {
		t.Fatalf("lsigprovider.Get(%q) = nil", KeyTypeV1)
	}
	if got := logicsigdsa.RoutingFamily(KeyTypeV1); got != FamilyName {
		t.Fatalf("RoutingFamily(%q) = %q, want %q", KeyTypeV1, got, FamilyName)
	}
}
