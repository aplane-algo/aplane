// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/aplane-algo/aplane/internal/hostmeta"
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

// goldenNativeFalconPayload pairs a fixed key pair with unrelated entropy; the
// stand-in validator does not check that the entropy derives the pair.
func goldenNativeFalconPayload(t *testing.T) *Payload {
	t.Helper()
	publicKey, privateKey, err := falcon.GenerateKey(bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return NewNativeFalconPayload(publicKey[:], privateKey[:], bytes.Repeat([]byte{0x22}, nativefalcon.RecoveryEntropySize))
}

// TestMarshalPayloadGoldenBytes pins the exact bytes MarshalPayload writes for
// every key category, above all those that carry private_key or
// recovery_entropy. A key file's encrypted payload is these bytes, so they
// must not change. The digests were taken from the encoder that held both
// fields as hex strings; the unsalted LogicSig ones were retaken when
// salt_counter was retired, and differ only by that line. native_pq's was
// retaken when native Falcon key files dropped pq_scheme and pq_address_salt
// and moved to format_version 1; keystest's
// TestPreChangeNativeFalconKeyJSONIsTheEarlierEncoding pins the earlier bytes.
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
		{"native_pq", goldenNativeFalconPayload(t), "57f9278481410d698d37dfceb80561bfbb39bef1791dface858c55b17b989362"},
		{"witness", NewWitnessPayload(witness.Falcon1024V1, componentPublic, componentPrivate), "d6e494aa574e43ba93dc1be7994fee193d6d57277bfaa5d0f7cf1e711a43d70f"},
		{"dsa_lsig", payloadWithOpcodeProfile(t, NewDSALSigPayload(
			"test.dsa.v1", "test.base.v1", []byte{0x01, 0x02}, []byte{0x03, 0x04},
			map[string]string{"network": "testnet"}, bytecode, "#pragma version 8\nint 1",
			[]StoredSigningArg{{Name: "proof", Type: "bytes", Required: true}}, "1:test",
		), false), "ec76dc72225d6b93c027c42443dacf65a4c249060457b6abefdcbd55a786489a"},
		// A host account's key: its contract under host, a bounded host's
		// with bounds and a plain host's without.
		{"dsa_lsig bounded host with a cosigner", cosignedTestPayload(t, hostmeta.DefaultCosignerComponentKeyType, ""), "7683f342130bbe240b04044c814004ee2524402b0ca8ab7814a53b98bf699391"},
		{"dsa_lsig plain host", goldenPlainHostPayload(t), "4babfadbe42c94fa94e4eff4c61940ef7b5afe1732d9fb3bede5836db5264f55"},
		{"rotating_lsig", NewRotatingLSigPayload(
			rotatingkey.RotatingTripleXmssV1,
			bytes.Repeat([]byte{0x31}, rotatingkey.RotatingSeedSize),
			bytes.Repeat([]byte{0x32}, rotatingkey.RotatingGenesisHashSize),
			bytes.Repeat([]byte{0x33}, profile.StagePublicKeySize),
		), "01167e6148ce7956c424547a5880667b431bebca0efedb413dbf43652afff4f4"},
		{"generic_lsig", payloadWithOpcodeProfile(t, NewGenericLSigPayload(
			"test.generic.v1", map[string]string{"recipient": "ALICE"}, bytecode,
			"#pragma version 8\nint 1", nil, "1:test",
		), false), "84466423aeaa8a91576ea96da7eae114c015cb8a2481686930a6786e6f963d9d"},
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

// goldenPlainHostPayload is a plain host account's key: host metadata with
// no bounds.
func goldenPlainHostPayload(t *testing.T) *Payload {
	t.Helper()
	layout := hostmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{4}}
	payload := NewDSALSigPayload("test.plain.v1", "test.base.v1", []byte{0x01}, []byte{0x02}, nil, canonicalOffCurveBytecode(t), "", nil, "1:plain")
	payloadWithOpcodeProfile(t, payload, true)
	if err := payload.SetHost(&hostmeta.Metadata{
		Contract: hostmeta.PlainContract, BaseSignatureArgLayout: layout,
		ArgumentLayout: hostmeta.BaseArgumentLayout(layout), Rekey: hostmeta.RekeyRefused,
	}); err != nil {
		t.Fatalf("SetHost(plain) error = %v", err)
	}
	return payload
}
