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
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

var canonicalTestTime = time.Date(2026, 7, 10, 12, 34, 56, 0, time.UTC)

func TestCanonicalPayloadFieldGoldens(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x11)
	componentPublicKey, componentPrivateKey := canonicalFalconComponentPair(t, 0x12)
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
			name:    "witness",
			payload: NewWitnessPayload(witness.Falcon1024V1, componentPublicKey, componentPrivateKey),
			fields:  []string{"category", "created_at", "format_version", "key_type", "private_key", "public_key"},
		},
		{
			name: "dsa_lsig",
			payload: payloadWithOpcodeProfile(t, NewDSALSigPayload(
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
			), false),
			fields: []string{
				"base_key_type", "category", "created_at", "format_version", "key_type",
				"lsig_bytecode", "lsig_opcode_profile", "parameters", "private_key", "public_key",
				"salt_counter", "signing_args", "signing_metadata_version", "teal_source",
				"template_fingerprint",
			},
		},
		{
			name: "generic_lsig",
			payload: payloadWithOpcodeProfile(t, NewGenericLSigPayload(
				"test.generic.v1",
				map[string]string{"recipient": "ALICE"},
				bytecode,
				0,
				"#pragma version 8\nint 1",
				nil,
				"1:test",
			), false),
			fields: []string{
				"category", "created_at", "format_version", "key_type", "lsig_bytecode",
				"lsig_opcode_profile", "parameters", "salt_counter", "signing_metadata_version",
				"teal_source", "template_fingerprint",
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

func payloadWithOpcodeProfile(t *testing.T, payload *Payload, bounded bool) *Payload {
	t.Helper()
	profile := lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling)
	if bounded {
		profile = lsigresource.BoundedOpcodeProfile(
			lsigresource.SingleTransactionOpcodeCeiling,
			lsigresource.SingleTransactionOpcodeCeiling,
			lsigresource.SingleTransactionOpcodeCeiling,
		)
	}
	if err := payload.SetLogicSigOpcodeProfile(profile, bounded); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestCanonicalPayloadRejectsStandaloneWitnessBundle(t *testing.T) {
	data := []byte(`{"schema":"aplane.witness-key-bundle.v1","key_type":"aplane.witness-falcon1024.v1","witness_key_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","public_key_hex":"00","encryption":{}}`)
	if _, err := ParsePayload(data); err == nil || !errors.Is(err, ErrIncompatibleKeyFormat) {
		t.Fatalf("ParsePayload(standalone witness bundle) error = %v, want incompatible format", err)
	}
}

func TestBoundedPayloadMetadataRoundTrip(t *testing.T) {
	bytecode := canonicalOffCurveBytecode(t)
	payload := NewDSALSigPayload(
		"test.bounded.v1", "test.base.v1", []byte{0x01}, []byte{0x02}, nil,
		bytecode, 0, "", []StoredSigningArg{{Name: "legacy_runtime_arg", Type: "bytes", MaxSize: 32}}, "1:bounded",
	)
	defer payload.ZeroSecrets()
	payload.CreatedAt = canonicalTestTime
	payloadWithOpcodeProfile(t, payload, true)
	metadata := &boundedmeta.Metadata{
		Contract: boundedmeta.ContractV1,
		BaseSignatureArgLayout: boundedmeta.SignatureArgLayout{
			Count: 1, MaxSizes: []int{4},
		},
		ArgumentLayout:  boundedmeta.BaseArgumentLayout(boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{4}}, false),
		SpendEffects:    []string{"pay", "axfer"},
		MaxFee:          1_000,
		AdminOperations: []boundedmeta.AdminOperation{{Kind: boundedmeta.AdminOperationRekey, Authorization: boundedmeta.AdminAuthorizationSpend, PolicyGate: boundedmeta.PolicyGateNone}},
		Layer3Policy:    boundedmeta.Layer3PolicyCustom,
	}
	if err := payload.SetBoundedAuthorization(metadata); err != nil {
		t.Fatalf("SetBoundedAuthorization() error = %v", err)
	}
	if payload.SigningArgs != nil {
		t.Fatalf("SetBoundedAuthorization() retained legacy signing args: %#v", payload.SigningArgs)
	}

	encoded, err := MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	defer zeroTestBytes(encoded)
	parsed, err := ParsePayload(encoded)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	defer parsed.ZeroSecrets()
	if parsed.SigningMetadataVersion != BoundedSigningMetadataVersion {
		t.Fatalf("SigningMetadataVersion = %d, want %d", parsed.SigningMetadataVersion, BoundedSigningMetadataVersion)
	}
	if got := parsed.BoundedAuthorization; got == nil || got.Contract != boundedmeta.ContractV1 || got.ArgumentBytesForPath(boundedmeta.PathSpend) != 4 {
		t.Fatalf("BoundedAuthorization = %#v", got)
	}

	metadata.SpendEffects[0] = "tampered"
	if parsed.BoundedAuthorization.SpendEffects[0] != "pay" {
		t.Fatal("bounded authorization metadata was not deep-copied")
	}
}

func TestBoundedSentryPayloadMetadataRoundTrip(t *testing.T) {
	bytecode := canonicalOffCurveBytecode(t)
	sentryPublicKey := bytes.Repeat([]byte{0x6d}, boundedmeta.SentryPublicKeySizeV1)
	componentKeyID, err := witness.ID(boundedmeta.SentryComponentKeyTypeV1, sentryPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := NewDSALSigPayload(
		"test.bounded-sentry.v1", "test.base.v1", []byte{0x01}, []byte{0x02},
		map[string]string{boundedmeta.SentryPublicKeyParameter: hex.EncodeToString(sentryPublicKey)},
		bytecode, 0, "", nil, "1:bounded-sentry",
	)
	defer payload.ZeroSecrets()
	payload.CreatedAt = canonicalTestTime
	payloadWithOpcodeProfile(t, payload, true)
	metadata := &boundedmeta.Metadata{
		Contract: boundedmeta.ContractV1, BaseSignatureArgLayout: boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{4}},
		SpendEffects: []string{boundedmeta.SpendEffectPay}, MaxFee: 1_000, Layer3Policy: boundedmeta.Layer3PolicyCustom,
		Sentry: &boundedmeta.SentryAuthorization{
			Contract: boundedmeta.SentryContractV1, ComponentKeyType: boundedmeta.SentryComponentKeyTypeV1,
			PublicKeyHex: hex.EncodeToString(sentryPublicKey), ComponentKeyID: componentKeyID,
			SignatureMaxSize: boundedmeta.SentrySignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
		ArgumentLayout: []boundedmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, AdminRekey: boundedmeta.ArgRequired}},
			{Index: 1, Name: boundedmeta.SentrySignatureSlot, Source: boundedmeta.ArgSourceSentry, MaxSize: boundedmeta.SentrySignatureMaxSizeV1, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden}},
		},
	}
	if err := payload.SetBoundedAuthorization(metadata); err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroTestBytes(encoded)
	parsed, err := ParsePayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.ZeroSecrets()
	if parsed.BoundedAuthorization.Sentry == nil || parsed.BoundedAuthorization.Sentry.ComponentKeyID != componentKeyID {
		t.Fatalf("sentry metadata = %#v", parsed.BoundedAuthorization.Sentry)
	}

	payload.Parameters[boundedmeta.SentryPublicKeyParameter] = strings.Repeat("00", boundedmeta.SentryPublicKeySizeV1)
	if _, err := MarshalPayload(payload); err == nil || !strings.Contains(err.Error(), "does not match parameters.sentry_public_key") {
		t.Fatalf("MarshalPayload() mismatch error = %v", err)
	}
}

func TestParsePayloadRejectsInvalidBoundedMetadata(t *testing.T) {
	bytecodeHex := hex.EncodeToString(canonicalOffCurveBytecode(t))
	base := `{"format_version":1}`
	base = strings.TrimSuffix(base, `}`) + `,"category":"dsa_lsig","key_type":"test.bounded.v1","public_key":"01","private_key":"02","lsig_bytecode":"` + bytecodeHex + `","salt_counter":0,"signing_metadata_version":2,"base_key_type":"test.base.v1","bounded_authorization":{"contract":"bounded1","base_signature_arg_layout":{"count":1,"max_sizes":[4]},"spend_effects":["pay"],"max_fee":1000,"admin_operations":[],"runtime_args":[],"derived_args":[],"argument_layout":[{"index":0,"name":"base_signature_0","source":"base_signature","max_size":4,"paths":{"spend":"required","spending_rekey":"required","admin_rekey":"required"}}],"layer3_policy":"custom"},"created_at":"2026-07-10T12:34:56Z"}`
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "obsolete combined size", data: strings.Replace(base, `"contract":"bounded1"`, `"contract":"bounded1","post_signing_lsig_size":9999`, 1), want: "unknown field"},
		{name: "unknown nested field", data: strings.Replace(base, `"contract":"bounded1"`, `"contract":"bounded1","future":true`, 1), want: "unknown field"},
		{name: "duplicate nested field", data: strings.Replace(base, `"contract":"bounded1"`, `"contract":"bounded1","contract":"bounded1"`, 1), want: `duplicate object member "contract"`},
		{name: "wrong metadata version", data: strings.Replace(base, `"signing_metadata_version":2`, `"signing_metadata_version":1`, 1), want: "requires signing_metadata_version 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParsePayload([]byte(tt.data))
			if payload != nil {
				payload.ZeroSecrets()
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParsePayload() error = %v, want %q", err, tt.want)
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

func TestAutoSaltedLogicSigPayloadContract(t *testing.T) {
	bytecode := canonicalOffCurveBytecodeForVersion(t, 13)
	payload := NewAutoSaltedGenericLSigPayload(
		"test.generic.v1", nil, bytecode, "#pragma version 13\nint 1", nil, "",
	)
	payloadWithOpcodeProfile(t, payload, false)
	payload.CreatedAt = canonicalTestTime
	if err := payload.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	encoded, err := MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	if strings.Contains(string(encoded), `"salt_counter"`) ||
		!strings.Contains(string(encoded), `"lsig_derivation": "algod_v13_auto_salt"`) ||
		!strings.Contains(string(encoded), `"lsig_opcode_profile"`) {
		t.Fatalf("auto-salted payload JSON = %s", encoded)
	}
	decoded, err := ParsePayload(encoded)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	defer decoded.ZeroSecrets()
	if decoded.LogicSigDerivation != LogicSigDerivationAlgodV13AutoSalt || decoded.SaltCounter != nil {
		t.Fatalf("decoded derivation = %q salt=%v", decoded.LogicSigDerivation, decoded.SaltCounter)
	}

	withCounter := *payload
	withCounter.SaltCounter = SaltCounterPtr(0)
	if err := withCounter.Validate(); err == nil || !strings.Contains(err.Error(), "forbids salt_counter") {
		t.Fatalf("Validate(auto-salted with counter) error = %v", err)
	}
	oldVersion := *payload
	oldVersion.LogicSigBytecode = canonicalOffCurveBytecodeForVersion(t, 12)
	if err := oldVersion.Validate(); err == nil || !strings.Contains(err.Error(), "requires final TEAL v13+") {
		t.Fatalf("Validate(auto-salted v12) error = %v", err)
	}
	unknown := *payload
	unknown.LogicSigDerivation = "future"
	if err := unknown.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported lsig_derivation") {
		t.Fatalf("Validate(unknown derivation) error = %v", err)
	}
}

func TestPayloadSelectorsComeFromAuthoritativeMaterial(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x33)
	componentPublicKey, componentPrivateKey := canonicalFalconComponentPair(t, 0x34)
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

	component := NewWitnessPayload(witness.Falcon1024V1, componentPublicKey, componentPrivateKey)
	defer component.ZeroSecrets()
	component.CreatedAt = canonicalTestTime
	wantComponent, err := witness.ID(component.KeyType, componentPublicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
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
	if err == nil || !strings.Contains(err.Error(), "public_key must be non-empty lowercase hex") {
		t.Fatalf("ParsePayload() error = %v, want lowercase rejection", err)
	}
}

// TestValidateEd25519PayloadRejectsSeedSuffixMismatch pins that validation
// re-derives from the seed: a payload whose private_key suffix and public_key
// agree with each other but not with the seed (which PrivateKey.Public() alone
// cannot detect) must be rejected instead of importing as an unusable key.
func TestValidateEd25519PayloadRejectsSeedSuffixMismatch(t *testing.T) {
	_, privA := canonicalEd25519Pair(t, 1)
	pubB, privB := canonicalEd25519Pair(t, 2)

	forged := append(append([]byte(nil), privA[:ed25519.SeedSize]...), pubB...)
	p := NewEd25519Payload(pubB, forged)
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "suffix does not match its seed") {
		t.Fatalf("Validate() error = %v, want seed/suffix mismatch rejection", err)
	}

	q := NewEd25519Payload(pubB, privA)
	if err := q.Validate(); err == nil || !strings.Contains(err.Error(), "public key does not match private key") {
		t.Fatalf("Validate() error = %v, want public-key mismatch rejection", err)
	}

	if err := NewEd25519Payload(pubB, privB).Validate(); err != nil {
		t.Fatalf("Validate(consistent pair) error = %v", err)
	}
}

func canonicalEd25519Pair(t *testing.T, fill byte) ([]byte, []byte) {
	t.Helper()
	seed := bytes.Repeat([]byte{fill}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return bytes.Clone(publicKey), bytes.Clone(privateKey)
}

func canonicalFalconComponentPair(t *testing.T, fill byte) ([]byte, []byte) {
	t.Helper()
	registerFalconComponentTestValidator.Do(func() {
		witness.RegisterPairValidator(witness.Falcon1024V1, func(publicKey, privateKey []byte) error {
			message := []byte("APLANE_COMPONENT_KEY_TEST_V1")
			signature, err := signerops.New(nil).Sign(privateKey, message)
			if err != nil {
				return err
			}
			return verify.VerifyFalcon1024(publicKey, message, signature)
		})
	})
	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{fill}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	return publicKey, privateKey
}

var registerFalconComponentTestValidator sync.Once

func canonicalOffCurveBytecode(t *testing.T) []byte {
	return canonicalOffCurveBytecodeForVersion(t, 6)
}

func canonicalOffCurveBytecodeForVersion(t *testing.T, version byte) []byte {
	t.Helper()
	for counter := 0; counter < 256; counter++ {
		bytecode := []byte{version, 0x81, 0x01, byte(counter)}
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
