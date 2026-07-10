// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

var canonicalTestTime = time.Date(2026, 7, 10, 12, 34, 56, 0, time.UTC)

func TestCanonicalPayloadFieldGoldens(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x11)
	bytecode := canonicalOffCurveBytecode(t)

	tests := []struct {
		name    string
		payload *Payload
		fields  []string
	}{
		{
			name:    "ed25519",
			payload: NewEd25519Payload(publicKey, privateKey),
			fields:  []string{"category", "created_at", "format_version", "key_type", "private_key", "public_key"},
		},
		{
			name:    "component",
			payload: NewComponentPayload(keytypes.SentryComponentEd25519V1, publicKey, privateKey),
			fields:  []string{"category", "created_at", "format_version", "key_type", "private_key", "public_key"},
		},
		{
			name: "dsa_lsig",
			payload: NewDSALSigPayload(
				"test.dsa.v1",
				"test.base.v1",
				[]byte{0x01, 0x02},
				[]byte{0x03, 0x04},
				map[string]string{"network": "testnet"},
				bytecode,
				0,
				"#pragma version 8\nint 1",
				[]StoredSigningArg{{Name: "proof", Type: "bytes", Required: true}},
				"1:test",
			),
			fields: []string{
				"base_key_type", "category", "created_at", "format_version", "key_type",
				"lsig_bytecode", "parameters", "private_key", "public_key", "salt_counter",
				"signing_args", "signing_metadata_version", "teal_source", "template_fingerprint",
			},
		},
		{
			name: "generic_lsig",
			payload: NewGenericLSigPayload(
				"test.generic.v1",
				map[string]string{"recipient": "ALICE"},
				bytecode,
				0,
				"#pragma version 8\nint 1",
				nil,
				"1:test",
			),
			fields: []string{
				"category", "created_at", "format_version", "key_type", "lsig_bytecode",
				"parameters", "salt_counter", "signing_metadata_version", "teal_source",
				"template_fingerprint",
			},
		},
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

			var object map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &object); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			gotFields := make([]string, 0, len(object))
			for name := range object {
				gotFields = append(gotFields, name)
			}
			slices.Sort(gotFields)
			if !slices.Equal(gotFields, tt.fields) {
				t.Fatalf("fields = %v, want %v\npayload: %s", gotFields, tt.fields, encoded)
			}
			for _, removed := range []string{"params", "bytecode_hex", "address", "template", "entropy", "derivation", "runtime_args"} {
				if _, ok := object[removed]; ok {
					t.Fatalf("canonical payload emitted removed field %q", removed)
				}
			}

			parsed, err := ParsePayload(encoded)
			if err != nil {
				t.Fatalf("ParsePayload() error = %v", err)
			}
			defer parsed.ZeroSecrets()
			if parsed.Category != tt.payload.Category || parsed.KeyType != tt.payload.KeyType {
				t.Fatalf("round trip = (%q, %q), want (%q, %q)", parsed.Category, parsed.KeyType, tt.payload.Category, tt.payload.KeyType)
			}
			if !bytes.Equal(parsed.PrivateKey, tt.payload.PrivateKey) || !bytes.Equal(parsed.LogicSigBytecode, tt.payload.LogicSigBytecode) {
				t.Fatal("round trip key material or bytecode mismatch")
			}
			if !maps.Equal(parsed.Parameters, tt.payload.Parameters) {
				t.Fatalf("round trip parameters = %#v, want %#v", parsed.Parameters, tt.payload.Parameters)
			}
		})
	}
}

func TestParsePayloadRejectsNonCanonicalJSON(t *testing.T) {
	bytecodeHex := hex.EncodeToString(canonicalOffCurveBytecode(t))
	base := `{"format_version":1,"category":"generic_lsig","key_type":"test.generic.v1","lsig_bytecode":"` + bytecodeHex + `","salt_counter":0,"signing_metadata_version":1,"created_at":"2026-07-10T12:34:56Z"}`

	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "unknown field", data: strings.TrimSuffix(base, "}") + `,"params":{}}`, want: "unknown field"},
		{name: "bytecode alias", data: strings.Replace(base, `"lsig_bytecode"`, `"bytecode_hex"`, 1), want: "unknown field"},
		{name: "top-level duplicate", data: strings.TrimSuffix(base, "}") + `,"key_type":"other"}`, want: `duplicate object member "key_type"`},
		{name: "parameter duplicate", data: strings.TrimSuffix(base, "}") + `,"parameters":{"recipient":"A","recipient":"B"}}`, want: `duplicate object member "recipient"`},
		{name: "signing arg duplicate", data: strings.TrimSuffix(base, "}") + `,"signing_args":[{"name":"proof","name":"other","type":"bytes"}]}`, want: `duplicate object member "name"`},
		{name: "nested duplicate before unknown rejection", data: strings.TrimSuffix(base, "}") + `,"future":{"nested":{"x":1,"x":2}}}`, want: `duplicate object member "x"`},
		{name: "null", data: strings.Replace(base, `"key_type":"test.generic.v1"`, `"key_type":null`, 1), want: "null values are not canonical"},
		{name: "trailing value", data: base + `{}`, want: "trailing JSON value"},
		{name: "top-level array", data: `[]`, want: "top-level value must be an object"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParsePayload([]byte(tt.data))
			if payload != nil {
				payload.ZeroSecrets()
				t.Fatalf("ParsePayload() payload = %#v, want nil", payload)
			}
			if !errors.Is(err, ErrIncompatibleKeyFormat) {
				t.Fatalf("ParsePayload() error = %v, want %v", err, ErrIncompatibleKeyFormat)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParsePayload() error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestPayloadCategoryValidation(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x22)
	bytecode := canonicalOffCurveBytecode(t)

	tests := []struct {
		name    string
		payload *Payload
		want    string
	}{
		{
			name: "native forbids parameters",
			payload: func() *Payload {
				p := NewEd25519Payload(publicKey, privateKey)
				p.Parameters = map[string]string{"unexpected": "value"}
				return p
			}(),
			want: "forbids LogicSig fields",
		},
		{
			name: "generic forbids private key",
			payload: func() *Payload {
				p := NewGenericLSigPayload("test.generic.v1", nil, bytecode, 0, "", nil, "")
				p.PrivateKey = []byte{0x01}
				return p
			}(),
			want: "forbids public_key and private_key",
		},
		{
			name: "dsa requires base key type",
			payload: NewDSALSigPayload(
				"test.dsa.v1", "", []byte{0x01}, []byte{0x02}, nil, bytecode, 0, "", nil, "",
			),
			want: "requires canonical base_key_type",
		},
		{
			name: "logic sig requires salt counter",
			payload: func() *Payload {
				p := NewGenericLSigPayload("test.generic.v1", nil, bytecode, 0, "", nil, "")
				p.SaltCounter = nil
				return p
			}(),
			want: ErrMissingLogicSigSaltCounter.Error(),
		},
		{
			name: "duplicate signing arg",
			payload: NewGenericLSigPayload(
				"test.generic.v1", nil, bytecode, 0, "",
				[]StoredSigningArg{{Name: "proof", Type: "bytes"}, {Name: "proof", Type: "bytes"}}, "",
			),
			want: "duplicate name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer tt.payload.ZeroSecrets()
			tt.payload.CreatedAt = canonicalTestTime
			err := tt.payload.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestPayloadSelectorsComeFromAuthoritativeMaterial(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x33)
	bytecode := canonicalOffCurveBytecode(t)

	native := NewEd25519Payload(publicKey, privateKey)
	defer native.ZeroSecrets()
	native.CreatedAt = canonicalTestTime
	var nativeAddress types.Address
	copy(nativeAddress[:], publicKey)
	wantNative := nativeAddress.String()
	gotNative, err := native.Selector()
	if err != nil {
		t.Fatalf("native Selector() error = %v", err)
	}
	if gotNative != wantNative {
		t.Fatalf("native Selector() = %q, want %q", gotNative, wantNative)
	}

	component := NewComponentPayload(keytypes.SentryComponentEd25519V1, publicKey, privateKey)
	defer component.ZeroSecrets()
	component.CreatedAt = canonicalTestTime
	wantComponent, err := keytypes.ComponentKeySelector(component.KeyType, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	gotComponent, err := component.Selector()
	if err != nil {
		t.Fatalf("component Selector() error = %v", err)
	}
	if gotComponent != wantComponent {
		t.Fatalf("component Selector() = %q, want %q", gotComponent, wantComponent)
	}

	generic := NewGenericLSigPayload("test.generic.v1", nil, bytecode, 0, "", nil, "")
	generic.CreatedAt = canonicalTestTime
	wantLogicSig, err := logicSigAddress(bytecode)
	if err != nil {
		t.Fatalf("logicSigAddress() error = %v", err)
	}
	gotLogicSig, err := generic.Selector()
	if err != nil {
		t.Fatalf("generic Selector() error = %v", err)
	}
	if gotLogicSig != wantLogicSig {
		t.Fatalf("generic Selector() = %q, want %q", gotLogicSig, wantLogicSig)
	}
}

func TestPayloadZeroSecrets(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x44)
	payload := NewEd25519Payload(publicKey, privateKey)
	owned := payload.PrivateKey
	payload.ZeroSecrets()
	if payload.PrivateKey != nil {
		t.Fatalf("PrivateKey = %x, want nil", payload.PrivateKey)
	}
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatalf("owned private key was not zeroed: %x", owned)
	}
}

func TestParsePayloadRejectsUppercaseHex(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x55)
	payload := NewEd25519Payload(publicKey, privateKey)
	payload.CreatedAt = canonicalTestTime
	encoded, err := MarshalPayload(payload)
	payload.ZeroSecrets()
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	defer zeroTestBytes(encoded)
	encoded = bytes.Replace(encoded, []byte(hex.EncodeToString(publicKey)), []byte(strings.ToUpper(hex.EncodeToString(publicKey))), 1)
	parsed, err := ParsePayload(encoded)
	if parsed != nil {
		parsed.ZeroSecrets()
	}
	if err == nil || !strings.Contains(err.Error(), "public_key must use lowercase hex") {
		t.Fatalf("ParsePayload() error = %v, want lowercase rejection", err)
	}
}

func canonicalEd25519Pair(t *testing.T, fill byte) ([]byte, []byte) {
	t.Helper()
	seed := bytes.Repeat([]byte{fill}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return bytes.Clone(publicKey), bytes.Clone(privateKey)
}

func canonicalOffCurveBytecode(t *testing.T) []byte {
	t.Helper()
	for counter := 0; counter < 256; counter++ {
		bytecode := []byte{0x06, 0x81, 0x01, byte(counter)}
		address, err := logicSigAddressBytes(bytecode)
		if err != nil {
			t.Fatalf("logicSigAddressBytes() error = %v", err)
		}
		if !lsigsalt.IsOnCurve(address) {
			return bytecode
		}
	}
	t.Fatal("failed to find off-curve test LogicSig bytecode")
	return nil
}

func canonicalOnCurveBytecode(t *testing.T) []byte {
	t.Helper()
	for counter := 0; counter < 256; counter++ {
		bytecode := []byte{0x06, 0x81, 0x01, byte(counter)}
		address, err := logicSigAddressBytes(bytecode)
		if err != nil {
			t.Fatalf("logicSigAddressBytes() error = %v", err)
		}
		if lsigsalt.IsOnCurve(address) {
			return bytecode
		}
	}
	t.Fatal("failed to find on-curve test LogicSig bytecode")
	return nil
}

func zeroTestBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
