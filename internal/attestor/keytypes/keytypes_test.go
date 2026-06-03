// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypes

import (
	"strings"
	"testing"
)

func TestAttestorKeyTypeClassifiers(t *testing.T) {
	if !IsAttestorComponentKeyType(AttestorComponentEd25519V1) {
		t.Fatal("component key type was not classified as component")
	}
	if !IsAttestedAccountKeyType(AttestedFalcon1024Ed25519V1) {
		t.Fatal("attested Falcon/Ed25519 account key type was not classified as attested")
	}
	if !IsAttestedAccountKeyType(AttestedEd25519Ed25519V1) {
		t.Fatal("optional attested Ed25519/Ed25519 account key type was not classified as attested")
	}
	if IsAttestorMVPKeyType("aplane.falcon1024.v1") {
		t.Fatal("ordinary Falcon key type classified as attestor MVP key type")
	}
}

func TestComponentKeyIDKnownVector(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}

	got, err := ComponentKeyID(AttestorComponentEd25519V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeyID() error = %v", err)
	}
	const want = "attkey_"
	if !strings.HasPrefix(got, want) {
		t.Fatalf("ComponentKeyID() = %q, want %q prefix", got, want)
	}
	if len(got) != len(ComponentKeyIDPrefix)+64 {
		t.Fatalf("ComponentKeyID() length = %d, want %d", len(got), len(ComponentKeyIDPrefix)+64)
	}
}

func TestComponentKeyIDRejectsNonComponentKeyType(t *testing.T) {
	_, err := ComponentKeyID(AttestedFalcon1024Ed25519V1, []byte{1})
	if err == nil {
		t.Fatal("ComponentKeyID() accepted attested account key type")
	}
}
