// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/algorand/falcon"
	"github.com/aplane-algo/aplane/internal/algorithm"
)

func TestCanonicalAddressMatchesPinnedVector(t *testing.T) {
	vector := loadKeyVector(t)
	entropy, err := hex.DecodeString(vector.EntropyHex)
	if err != nil {
		t.Fatal(err)
	}
	seedInput := append([]byte("PQK"+Scheme), entropy...)
	seed := sha512.Sum512_256(seedInput)
	publicKey, privateKey, err := falcon.GenerateKey(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	publicHash := sha512.Sum512_256(publicKey[:])
	privateHash := sha512.Sum512_256(privateKey[:])
	if got := hex.EncodeToString(publicHash[:]); got != vector.PublicKeySHA512256 {
		t.Fatalf("public key digest = %s, want %s", got, vector.PublicKeySHA512256)
	}
	if got := hex.EncodeToString(privateHash[:]); got != vector.PrivateKeySHA512256 {
		t.Fatalf("private key digest = %s, want %s", got, vector.PrivateKeySHA512256)
	}
	salt, address, err := CanonicalAddress(publicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if salt != vector.Salt || address.String() != vector.Address {
		t.Fatalf("canonical address = (%d, %s), want (%d, %s)", salt, address, vector.Salt, vector.Address)
	}
	if !IsCompliant(address) {
		t.Fatal("canonical address is not PQ compliant")
	}
}

func TestAddressRejectsWrongPublicKeySize(t *testing.T) {
	if _, err := Address(0, make([]byte, PublicKeySize-1)); err == nil {
		t.Fatal("Address() accepted a short public key")
	}
}

func TestRegisterClientExposesNativePQMetadata(t *testing.T) {
	RegisterClient()
	meta, err := algorithm.GetMetadata(KeyType)
	if err != nil {
		t.Fatal(err)
	}
	if meta.AuthorizationKind() != algorithm.AuthorizationNativePQ {
		t.Fatalf("authorization kind = %q, want %q", meta.AuthorizationKind(), algorithm.AuthorizationNativePQ)
	}
	if meta.RequiresLogicSig() {
		t.Fatal("native Falcon metadata requires LogicSig")
	}
	if got := algorithm.DisplayLabel(meta); got != "native post-quantum" {
		t.Fatalf("display label = %q", got)
	}
}
