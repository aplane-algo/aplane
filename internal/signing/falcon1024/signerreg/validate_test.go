// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
)

func nativePayload(t *testing.T, entropyByte byte) *keys.Payload {
	t.Helper()
	entropy := make([]byte, nativefalcon.RecoveryEntropySize)
	for i := range entropy {
		entropy[i] = entropyByte + byte(i)
	}
	publicKey, privateKey, err := signerops.DeriveKeyPair(entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(privateKey[:])
	return keys.NewNativeFalconPayload(publicKey[:], privateKey[:], entropy)
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
	if parsed.Category != keys.CategoryNativePQ || parsed.FormatVersion != keys.CurrentKeyFormatVersion {
		t.Fatalf("parsed native PQ payload is category %q, format %d", parsed.Category, parsed.FormatVersion)
	}
	_, address, err := keys.NativePQAddress(nativefalcon.KeyType, parsed.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if selector, err := parsed.Selector(); err != nil || selector != address.String() {
		t.Fatalf("Selector() = %q, %v; want the derived address %s", selector, err, address)
	}
}

func TestNativePQPayloadRejectsMismatchedPair(t *testing.T) {
	RegisterKeyValidator()
	first := nativePayload(t, 0)
	defer first.ZeroSecrets()
	second := nativePayload(t, 1)
	defer second.ZeroSecrets()

	first.PrivateKey = append(first.PrivateKey[:0], second.PrivateKey...)
	if err := first.Validate(); err == nil {
		t.Fatal("Validate() accepted mismatched Falcon key pair")
	}
}

func TestNativeRecoveryPayloadRoundTripAndValidation(t *testing.T) {
	RegisterKeyValidator()
	payload := nativePayload(t, 0)
	defer payload.ZeroSecrets()
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
	parsed.RecoveryEntropy[0] ^= 1
	if err := parsed.Validate(); err == nil {
		t.Fatal("mismatched entropy accepted")
	}
	parsed.RecoveryEntropy[0] ^= 1
	entropy := parsed.RecoveryEntropy
	for _, tc := range []struct {
		name   string
		format int
		trim   int
		want   string
	}{
		{"format 2", 2, 32, "incompatible key file format: format_version 2 is not supported by this runtime; expected 1; restore or regenerate the key file using the current key schema"},
		{"short entropy", 1, 31, "incompatible key file format: native Falcon recovery_entropy length 31 invalid (expected 32 bytes); restore or regenerate the key file using the current key schema"},
		{"no entropy", 1, 0, "incompatible key file format: native Falcon recovery_entropy length 0 invalid (expected 32 bytes); restore or regenerate the key file using the current key schema"},
	} {
		parsed.FormatVersion, parsed.RecoveryEntropy = tc.format, entropy[:tc.trim]
		if err := parsed.Validate(); err == nil || err.Error() != tc.want {
			t.Fatalf("%s: Validate() error = %v, want %q", tc.name, err, tc.want)
		}
	}
	parsed.FormatVersion, parsed.RecoveryEntropy = keys.CurrentKeyFormatVersion, entropy
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

// preChangeNativeFalconRefusal is what both parses report for a native Falcon
// key file from before key files dropped pq_scheme and pq_address_salt. The
// decoder stops at the first retired field, so a format 1 file without
// recovery entropy gets the same refusal.
const preChangeNativeFalconRefusal = `incompatible key file format: failed to decode canonical payload: json: unknown field "pq_scheme"; restore or regenerate the key file using the current key schema`

// A native Falcon key file from before key files dropped pq_scheme and
// pq_address_salt, with or without recovery entropy, is refused by both
// parses. The two writers never wrote another native Falcon shape.
func TestPreChangeNativeFalconKeyFilesAreRefused(t *testing.T) {
	RegisterKeyValidator()
	entropy := bytes.Repeat([]byte{0x5a}, nativefalcon.RecoveryEntropySize)
	_, current := keystest.NativeFalconKeyJSON(t, entropy)
	defer crypto.ZeroBytes(current)
	for _, tc := range []struct {
		name     string
		recovery bool
		want     string
	}{
		{"format 2 with recovery entropy", true, preChangeNativeFalconRefusal},
		{"format 1 without recovery entropy", false, preChangeNativeFalconRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preChange := keystest.PreChangeNativeFalconKeyJSON(t, current, tc.recovery)
			defer crypto.ZeroBytes(preChange)
			for parse, fn := range map[string]func([]byte) (*keys.Payload, error){
				"ParsePayload":       keys.ParsePayload,
				"ParseStoredPayload": keys.ParseStoredPayload,
			} {
				payload, err := fn(preChange)
				got := ""
				if err != nil {
					got = err.Error()
				} else {
					payload.ZeroSecrets()
				}
				if got != tc.want {
					t.Fatalf("%s() error = %q, want %q", parse, got, tc.want)
				}
			}
		})
	}
}
