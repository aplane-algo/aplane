// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"crypto/sha512"
	"testing"

	"github.com/algorand/falcon"
	"github.com/aplane-algo/aplane/internal/keys"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

func nativePayload(t *testing.T, entropyByte byte) *keys.Payload {
	t.Helper()
	entropy := make([]byte, nativefalcon.RecoveryEntropySize)
	for i := range entropy {
		entropy[i] = entropyByte + byte(i)
	}
	input := append([]byte("PQK"+nativefalcon.Scheme), entropy...)
	seed := sha512.Sum512_256(input)
	publicKey, privateKey, err := falcon.GenerateKey(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	salt, _, err := nativefalcon.CanonicalAddress(publicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewNativeFalconPayload(publicKey[:], privateKey[:], salt)
}

func TestNativePQPayloadRoundTrip(t *testing.T) {
	RegisterKeyValidator()
	payload := nativePayload(t, 0)
	defer payload.ZeroSecrets()
	encoded, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := keys.ParsePayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.ZeroSecrets()
	if parsed.Category != keys.CategoryNativePQ || parsed.PQScheme != nativefalcon.Scheme || parsed.PQAddressSalt == nil {
		t.Fatalf("parsed native PQ metadata = %#v", parsed)
	}
	selector, err := parsed.Selector()
	if err != nil || len(selector) != 58 {
		t.Fatalf("Selector() = %q, %v", selector, err)
	}
}

func TestNativePQPayloadRejectsMismatchedPairAndSalt(t *testing.T) {
	RegisterKeyValidator()
	first := nativePayload(t, 0)
	defer first.ZeroSecrets()
	second := nativePayload(t, 1)
	defer second.ZeroSecrets()

	first.PrivateKey = append(first.PrivateKey[:0], second.PrivateKey...)
	if err := first.Validate(); err == nil {
		t.Fatal("Validate() accepted mismatched Falcon key pair")
	}

	first = nativePayload(t, 2)
	defer first.ZeroSecrets()
	*first.PQAddressSalt++
	if err := first.Validate(); err == nil {
		t.Fatal("Validate() accepted noncanonical native PQ salt")
	}
}
