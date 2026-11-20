// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestMarshalAutoSaltedPayloadGoldenBytes pins the bytes MarshalPayload writes
// for the auto-salted LogicSig constructors, which build on the unsalted ones.
// The digests were taken before those lost their salt counter parameter, and
// held when salt_counter was retired from the payload.
func TestMarshalAutoSaltedPayloadGoldenBytes(t *testing.T) {
	bytecode := canonicalOffCurveBytecodeForVersion(t, 13)
	for _, tt := range []struct {
		name    string
		payload *Payload
		digest  string
	}{
		{"dsa_lsig", payloadWithOpcodeProfile(t, NewAutoSaltedDSALSigPayload(
			"test.dsa.v1", "test.base.v1", []byte{0x01, 0x02}, []byte{0x03, 0x04},
			map[string]string{"network": "testnet"}, bytecode, "#pragma version 13\nint 1",
			[]StoredSigningArg{{Name: "proof", Type: "bytes", Required: true}}, "1:test",
		), false), "f1f206c5ad27a1e32706bc182d0052d4e53a0ef2b42a9801658d961bb4e90227"},
		{"generic_lsig", payloadWithOpcodeProfile(t, NewAutoSaltedGenericLSigPayload(
			"test.generic.v1", map[string]string{"recipient": "ALICE"}, bytecode,
			"#pragma version 13\nint 1", nil, "1:test",
		), false), "38ab47083cb34eaa0e1e32d8dac41de5043acbcf3d33630846e4c084f9371bba"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.payload.CreatedAt = canonicalTestTime
			defer tt.payload.ZeroSecrets()
			encoded, err := MarshalPayload(tt.payload)
			if err != nil {
				t.Fatalf("MarshalPayload() error = %v", err)
			}
			defer zeroTestBytes(encoded)
			sum := sha256.Sum256(encoded)
			if got := hex.EncodeToString(sum[:]); got != tt.digest {
				t.Fatalf("MarshalPayload() digest = %s, want %s", got, tt.digest)
			}
		})
	}
}
