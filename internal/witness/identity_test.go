// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestIDKnownVector(t *testing.T) {
	publicKey := make([]byte, Falcon1024PublicKeySize)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}

	got, err := ID(Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("ID() error = %v", err)
	}
	const want = "6VY7A6IRYQVODHJ7QSLURSEZSYIR5VKMAPSHKNTGTYMH4GTEHA7Q"
	if got != want {
		t.Fatalf("ID() = %q, want %q", got, want)
	}
	if len(got) != IDLength || !IsID(got) {
		t.Fatalf("ID() = %q is not a canonical Witness Key ID", got)
	}
	if _, err := types.DecodeAddress(got); err == nil {
		t.Fatalf("ID() = %q decoded as an Algorand address", got)
	}
}

// An Ed25519 witness key has its own sizes, and its Witness Key ID binds the
// type: the same 32 bytes under another type give another ID.
func TestEd25519WitnessKeyType(t *testing.T) {
	if !IsKeyType(Ed25519V1) {
		t.Fatalf("IsKeyType(%s) = false", Ed25519V1)
	}
	if size, ok := PublicKeySize(Ed25519V1); !ok || size != 32 {
		t.Fatalf("PublicKeySize() = %d, %v; want 32", size, ok)
	}
	if size, ok := PrivateKeySize(Ed25519V1); !ok || size != 64 {
		t.Fatalf("PrivateKeySize() = %d, %v; want 64", size, ok)
	}
	publicKey := make([]byte, Ed25519PublicKeySize)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}
	got, err := ID(Ed25519V1, publicKey)
	if err != nil {
		t.Fatalf("ID() error = %v", err)
	}
	if got != DeriveID(Ed25519V1, publicKey) || got == DeriveID(Falcon1024V1, publicKey) {
		t.Fatalf("ID() = %q does not bind the key type", got)
	}
	if len(got) != IDLength || !IsID(got) {
		t.Fatalf("ID() = %q is not a canonical Witness Key ID", got)
	}
	if _, err := ID(Ed25519V1, make([]byte, Falcon1024PublicKeySize)); err == nil {
		t.Fatal("ID() accepted a Falcon-sized key for an Ed25519 witness")
	}
	// Only an Ed25519 key's public key is also an address.
	if address, hasAddress, err := AccountAddress(Ed25519V1, publicKey); !hasAddress || err != nil || string(address[:]) != string(publicKey) {
		t.Fatalf("AccountAddress(Ed25519) = %x, %t, %v", address, hasAddress, err)
	}
	if _, hasAddress, err := AccountAddress(Falcon1024V1, make([]byte, Falcon1024PublicKeySize)); hasAddress || err != nil {
		t.Fatalf("AccountAddress(Falcon) = %t, %v; want no address", hasAddress, err)
	}
	if _, hasAddress, err := AccountAddress(Ed25519V1, publicKey[:31]); !hasAddress || err == nil {
		t.Fatalf("AccountAddress(short Ed25519) = %t, %v; want an error", hasAddress, err)
	}
	// The vectors the SDKs pin for their own derivation.
	zeros := make([]byte, Ed25519PublicKeySize)
	if got, _ := ID(Ed25519V1, zeros); got != "MMN7TOWCUUIJP2VKT5JJW7RC5J6S5LZEHPDNAKEW4G4KYV6XCJJQ" {
		t.Fatalf("ID(zeros) = %s", got)
	}
	counting := make([]byte, Ed25519PublicKeySize)
	for i := range counting {
		counting[i] = byte(i % 251)
	}
	if got, _ := ID(Ed25519V1, counting); got != "G6RCBPAWGJ7FHBXANDLJ2JYG2THQUKREIUCIRKAVDWEKAOBOJTVQ" {
		t.Fatalf("ID(i mod 251) = %s", got)
	}
}

func TestIDRejectsUnsupportedTypeAndLength(t *testing.T) {
	if _, err := ID("aplane.unknown.v1", make([]byte, Falcon1024PublicKeySize)); err == nil {
		t.Fatal("ID() accepted unsupported key type")
	}
	if _, err := ID(Falcon1024V1, make([]byte, Falcon1024PublicKeySize-1)); err == nil {
		t.Fatal("ID() accepted wrong public-key length")
	}
}

func TestNormalizeIDRejectsInvalidValues(t *testing.T) {
	tests := []string{
		"",
		"not-an-id",
		strings.Repeat("A", IDLength-1),
		strings.Repeat("A", IDLength+1),
		strings.ToLower(strings.Repeat("A", IDLength)),
		strings.Repeat("A", IDLength-1) + "=",
		strings.Repeat("0", IDLength),
	}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			if IsID(value) {
				t.Fatalf("IsID(%q) = true, want false", value)
			}
		})
	}
}
