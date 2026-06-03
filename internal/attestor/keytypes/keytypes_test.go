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
	const want = "attkey_c180fb1cce27fcf3bb4f26403a47466216cfa206a0759439d3bd1498bc3a99d0"
	if got != want {
		t.Fatalf("ComponentKeyID() = %q, want %q", got, want)
	}
	if !IsComponentKeyID(got) {
		t.Fatalf("IsComponentKeyID(%q) = false, want true", got)
	}
}

func TestComponentKeyIDRejectsNonComponentKeyType(t *testing.T) {
	_, err := ComponentKeyID(AttestedFalcon1024V1, []byte{1})
	if err == nil {
		t.Fatal("ComponentKeyID() accepted attested account key type")
	}
}

func TestIsComponentKeyIDRejectsInvalidHandles(t *testing.T) {
	tests := []string{
		"",
		"not-an-address",
		"attkey_",
		"attkey_zzzz",
		"attkey_c180fb1cce27fcf3bb4f26403a47466216cfa206a0759439d3bd1498bc3a99",
		"c180fb1cce27fcf3bb4f26403a47466216cfa206a0759439d3bd1498bc3a99d0",
	}
	for _, id := range tests {
		t.Run(id, func(t *testing.T) {
			if IsComponentKeyID(id) {
				t.Fatalf("IsComponentKeyID(%q) = true, want false", id)
			}
		})
	}
}
