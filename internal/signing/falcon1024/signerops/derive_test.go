// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import "testing"

func TestDeriveKeyPairIsDeterministicAndSized(t *testing.T) {
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	pub1, priv1, err := DeriveKeyPair(entropy)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := DeriveKeyPair(entropy)
	if err != nil {
		t.Fatal(err)
	}
	if pub1 != pub2 || priv1 != priv2 {
		t.Fatal("derivation is not deterministic")
	}
	entropy[0] ^= 1
	if pub3, _, err := DeriveKeyPair(entropy); err != nil || pub3 == pub1 {
		t.Fatal("different entropy derived the same key pair")
	}
	for _, size := range []int{0, 31, 33} {
		if _, _, err := DeriveKeyPair(make([]byte, size)); err == nil {
			t.Fatalf("accepted %d-byte entropy", size)
		}
	}
}
