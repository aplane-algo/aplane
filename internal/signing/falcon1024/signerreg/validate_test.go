// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"github.com/aplane-algo/aplane/internal/crypto"
	"strings"
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

func TestNativeRecoveryPayloadRoundTripAndValidation(t *testing.T) {
	RegisterKeyValidator()
	payload := nativePayload(t, 0)
	defer payload.ZeroSecrets()
	payload.FormatVersion = keys.NativeRecoveryKeyFormatVersion
	payload.RecoveryEntropy = make([]byte, 32)
	for i := range payload.RecoveryEntropy {
		payload.RecoveryEntropy[i] = byte(i)
	}
	encoded, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(encoded)
	parsed, err := keys.ParsePayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.ZeroSecrets()
	if !bytes.Equal(parsed.RecoveryEntropy, payload.RecoveryEntropy) {
		t.Fatal("entropy lost")
	}
	metadata, err := json.Marshal(parsed.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(metadata, []byte("recovery_entropy")) {
		t.Fatal("secret projected as metadata")
	}
	if !parsed.RecoveryPhraseAvailable() {
		t.Fatal("format 2 Falcon payload not marked phrase-recoverable")
	}
	parsed.RecoveryEntropy[0] ^= 1
	if err := parsed.Validate(); err == nil {
		t.Fatal("mismatched entropy accepted")
	}
	parsed.RecoveryEntropy[0] ^= 1
	parsed.FormatVersion = 1
	if err := parsed.Validate(); err == nil {
		t.Fatal("v1 entropy accepted")
	}
	parsed.FormatVersion = 2
	parsed.RecoveryEntropy = parsed.RecoveryEntropy[:31]
	if err := parsed.Validate(); err == nil {
		t.Fatal("short entropy accepted")
	}
	secret := payload.RecoveryEntropy
	payload.ZeroSecrets()
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("entropy not zeroed")
	}
}

// TestStoredPayloadParseDefersRecoveryDerivation pins the split between the
// full admission parse and the hot stored-credential parse: only the former
// re-derives the key pair from recovery entropy.
func TestStoredPayloadParseDefersRecoveryDerivation(t *testing.T) {
	RegisterKeyValidator()
	payload := nativePayload(t, 0)
	defer payload.ZeroSecrets()
	encoded, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(encoded)
	// Swap in entropy that does not derive this pair, bypassing MarshalPayload.
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire["format_version"] = keys.NativeRecoveryKeyFormatVersion
	wire["recovery_entropy"] = strings.Repeat("ab", 32)
	mismatched, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(mismatched)
	if parsed, err := keys.ParsePayload(mismatched); err == nil {
		parsed.ZeroSecrets()
		t.Fatal("full parse accepted entropy that does not derive the key pair")
	}
	parsed, err := keys.ParseStoredPayload(mismatched)
	if err != nil {
		t.Fatalf("stored parse rejected structurally valid payload: %v", err)
	}
	parsed.ZeroSecrets()
	wire["recovery_entropy"] = strings.Repeat("ab", 31)
	short, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := keys.ParseStoredPayload(short); err == nil {
		parsed.ZeroSecrets()
		t.Fatal("stored parse accepted short recovery entropy")
	}
}
