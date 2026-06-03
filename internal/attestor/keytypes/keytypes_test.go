// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypes

import "testing"

func TestAttestorKeyTypeClassifiers(t *testing.T) {
	if !IsAttestorComponentKeyType(AttestorComponentEd25519V1) {
		t.Fatal("component key type was not classified as component")
	}
	if !IsAttestedAccountKeyType(AttestedFalcon1024V1) {
		t.Fatal("attested Falcon account key type was not classified as attested")
	}
	if !IsAttestedAccountKeyType(AttestedEd25519V1) {
		t.Fatal("optional attested Ed25519 account key type was not classified as attested")
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
	const want = "attkey_14b2f812b37b88149dd2d15e53a3e70b1ec4759514b1b0b0238a43018ab4d848"
	if got != want {
		t.Fatalf("ComponentKeyID() = %q, want %q", got, want)
	}
}

func TestComponentKeyIDRejectsNonComponentKeyType(t *testing.T) {
	_, err := ComponentKeyID(AttestedFalcon1024V1, []byte{1})
	if err == nil {
		t.Fatal("ComponentKeyID() accepted attested account key type")
	}
}
