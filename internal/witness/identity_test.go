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
