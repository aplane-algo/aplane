// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/algorand/falcon"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/witness"
)

// goldenTestCodecs registers stand-ins for the native Falcon key-pair
// validator and one rotating codec, which only the signer links. They accept
// any pair: these tests pin the encoding, not the key checks.
var goldenTestCodecs sync.Once

func registerGoldenTestCodecs() {
	goldenTestCodecs.Do(func() {
		RegisterNativePQKeyPairValidator(nativefalcon.Scheme, func(_, _, _ []byte) error { return nil })
		RegisterRotatingCodec(rotatingkey.RotatingTripleXmssV1, RotatingCodec{
			AccountAddress: func([]byte) (string, error) { return "GOLDEN", nil },
			ValidateSeed:   func(_, _, _ []byte) error { return nil },
		})
	})
}

func goldenNativeFalconPayload(t *testing.T, withEntropy bool) *Payload {
	t.Helper()
	publicKey, privateKey, err := falcon.GenerateKey(bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	salt, _, err := nativefalcon.CanonicalAddress(publicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	payload := NewNativeFalconPayload(publicKey[:], privateKey[:], salt)
	if withEntropy {
		payload.FormatVersion = NativeRecoveryKeyFormatVersion
		payload.RecoveryEntropy = bytes.Repeat([]byte{0x22}, nativefalcon.RecoveryEntropySize)
	}
	return payload
}

// TestMarshalPayloadGoldenBytes pins the exact bytes MarshalPayload writes for
// every key category, above all those that carry private_key or
// recovery_entropy. A key file's encrypted payload is these bytes, so they
// must not change. The digests were taken from the encoder that held both
// fields as hex strings.
func TestMarshalPayloadGoldenBytes(t *testing.T) {
	registerGoldenTestCodecs()
	edPublic, edPrivate := canonicalEd25519Pair(t, 0x11)
	componentPublic, componentPrivate := canonicalFalconComponentPair(t, 0x12)
	bytecode := canonicalOffCurveBytecode(t)
	profile, _ := rotatingkey.Lookup(rotatingkey.RotatingTripleXmssV1)

	tests := []struct {
		name    string
		payload *Payload
		digest  string
	}{
		{"ed25519", NewEd25519Payload(edPublic, edPrivate), "e8a4354115b677b16da4cf36b69b7bcb24d99b4f61494e13fdf56826810c03ea"},
		{"native_pq", goldenNativeFalconPayload(t, false), "edfaac7e7dd8f9d165400b125d003c75b5d687b86e4d295d11cbf3292832fb31"},
		{"native_pq with recovery entropy", goldenNativeFalconPayload(t, true), "0e2ae0dde698b9c1b4469e11de9bf757934c9d8fa18bd3aaa66d64b92f7a6b1e"},
		{"witness", NewWitnessPayload(witness.Falcon1024V1, componentPublic, componentPrivate), "d6e494aa574e43ba93dc1be7994fee193d6d57277bfaa5d0f7cf1e711a43d70f"},
		{"dsa_lsig", payloadWithOpcodeProfile(t, NewDSALSigPayload(
			"test.dsa.v1", "test.base.v1", []byte{0x01, 0x02}, []byte{0x03, 0x04},
			map[string]string{"network": "testnet"}, bytecode, "#pragma version 8\nint 1",
			[]StoredSigningArg{{Name: "proof", Type: "bytes", Required: true}}, "1:test",
		), false), "fddba8e4d2e43803060d8bbb32aeaf289bd3be0cc065c26f0af4d4b37e1b39c5"},
		{"rotating_lsig", NewRotatingLSigPayload(
			rotatingkey.RotatingTripleXmssV1,
			bytes.Repeat([]byte{0x31}, rotatingkey.RotatingSeedSize),
			bytes.Repeat([]byte{0x32}, rotatingkey.RotatingGenesisHashSize),
			bytes.Repeat([]byte{0x33}, profile.StagePublicKeySize),
		), "01167e6148ce7956c424547a5880667b431bebca0efedb413dbf43652afff4f4"},
		{"generic_lsig", payloadWithOpcodeProfile(t, NewGenericLSigPayload(
			"test.generic.v1", map[string]string{"recipient": "ALICE"}, bytecode,
			"#pragma version 8\nint 1", nil, "1:test",
		), false), "19addbe5b44e24b9d37a430f92f7e2be6c7d347ea2bb5371fddfc1dc4f4e7e41"},
	}
	for _, tt := range tests {
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
				t.Fatalf("MarshalPayload() digest = %s, want %s (%d bytes)", got, tt.digest, len(encoded))
			}
			parsed, err := ParsePayload(encoded)
			if err != nil {
				t.Fatalf("ParsePayload() error = %v", err)
			}
			defer parsed.ZeroSecrets()
			if !bytes.Equal(parsed.PrivateKey, tt.payload.PrivateKey) || !bytes.Equal(parsed.RecoveryEntropy, tt.payload.RecoveryEntropy) {
				t.Fatal("round trip changed the private key or recovery entropy")
			}
		})
	}
}
