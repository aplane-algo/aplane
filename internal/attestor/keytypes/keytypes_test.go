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
	if IsAttestorMVPKeyType("aplane.falcon1024.v1") {
		t.Fatal("ordinary Falcon key type classified as attestor MVP key type")
	}
	if IsAttestorMVPKeyType("aplane.future-attested.v1") {
		t.Fatal("deferred future attested key type classified as MVP key type")
	}
}

func TestComponentKeySelectorKnownVector(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}

	got, err := ComponentKeySelector(AttestorComponentEd25519V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	const want = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if got != want {
		t.Fatalf("ComponentKeySelector() = %q, want %q", got, want)
	}
	if !IsComponentKeySelector(got) {
		t.Fatalf("IsComponentKeySelector(%q) = false, want true", got)
	}
}

func TestComponentKeySelectorRejectsNonComponentKeyType(t *testing.T) {
	_, err := ComponentKeySelector(AttestedFalcon1024V1, make([]byte, 32))
	if err == nil {
		t.Fatal("ComponentKeySelector() accepted attested account key type")
	}
}

func TestNormalizeComponentKeySelector(t *testing.T) {
	const want = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	got, err := NormalizeComponentKeySelector("0X000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	if err != nil {
		t.Fatalf("NormalizeComponentKeySelector() error = %v", err)
	}
	if got != want {
		t.Fatalf("NormalizeComponentKeySelector() = %q, want %q", got, want)
	}
}

func TestIsComponentKeySelectorRejectsInvalidValues(t *testing.T) {
	tests := []string{
		"",
		"not-an-address",
		"zzzz",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	}
	for _, id := range tests {
		t.Run(id, func(t *testing.T) {
			if IsComponentKeySelector(id) {
				t.Fatalf("IsComponentKeySelector(%q) = true, want false", id)
			}
		})
	}
}
