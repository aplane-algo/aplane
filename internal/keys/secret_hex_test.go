// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// A secretHex field encodes exactly as the hex string field it replaced,
// compact or indented, and is left out when empty.
func TestSecretHexEncodesAsTheHexString(t *testing.T) {
	type asBytes struct {
		F secretHex[privateKeyField] `json:"f,omitempty"`
	}
	type asString struct {
		F string `json:"f,omitempty"`
	}
	for _, secret := range [][]byte{nil, {0x00}, {0xab, 0xcd}, bytes.Repeat([]byte{0x5a, 0xa5}, 1153)} {
		got, err := json.MarshalIndent(asBytes{newSecretHex[privateKeyField](secret)}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.MarshalIndent(asString{hex.EncodeToString(secret)}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("secret %x encodes as %s, want %s", secret, got, want)
		}
	}
}

// Decoding a secretHex field accepts and refuses exactly what decoding a
// string and applying decodeCanonicalHex did, with the same errors.
func TestSecretHexDecodesAsDecodeCanonicalHex(t *testing.T) {
	for _, token := range []string{
		`"0a1b"`, `""`, `"0A1B"`, `"0a1"`, `"0g"`, `"zz"`, `" 0a"`,
		`"0a"`, `"Ab"`, `"0a\n"`, `"\/0"`, `"é0"`, `"0É"`, "\"0\xff\"",
	} {
		var asBytes struct {
			F secretHex[privateKeyField] `json:"f"`
		}
		var asString struct {
			F string `json:"f"`
		}
		body := []byte(`{"f":` + token + `}`)
		if err := json.Unmarshal(body, &asBytes); err != nil {
			t.Fatalf("%s: unmarshal as secretHex: %v", token, err)
		}
		if err := json.Unmarshal(body, &asString); err != nil {
			t.Fatalf("%s: unmarshal as string: %v", token, err)
		}
		got, gotErr := asBytes.F.decode()
		want, wantErr := decodeCanonicalHex("private_key", asString.F)
		if !bytes.Equal(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
			t.Fatalf("%s: decode = %x, %v; want %x, %v", token, got, gotErr, want, wantErr)
		}
	}
}

// decodeSecretFields decodes body into the wire struct as parsePayload does.
func decodeSecretFields(body []byte) error {
	var wire payloadWire
	defer wire.zeroSecrets()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&wire)
}

// A secret field holding a value that is not a string is refused with the
// error the string field gave, naming the field.
func TestSecretHexRefusesNonStringsAsTheStringFieldDid(t *testing.T) {
	// payloadWire as it was, with the secrets as strings.
	type payloadWire struct {
		PrivateKeyHex      string `json:"private_key,omitempty"`
		RecoveryEntropyHex string `json:"recovery_entropy,omitempty"`
	}
	for _, field := range []string{"private_key", "recovery_entropy"} {
		for _, value := range []string{`12`, `-1.5e3`, `true`, `false`, `{}`, `{"a":1}`, `[]`, `[1,"x"]`} {
			body := []byte(`{"` + field + `":` + value + `}`)
			var old payloadWire
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			want := decoder.Decode(&old)
			got := decodeSecretFields(body)
			if want == nil || fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("%s: error = %v, want %v", body, got, want)
			}
		}
	}
}

// A field decoded a second time, as a case-variant duplicate member is,
// zeroes the value it replaces.
func TestSecretHexUnmarshalZeroesTheValueItReplaces(t *testing.T) {
	var h secretHex[privateKeyField]
	if err := h.UnmarshalJSON([]byte(`"aaaa"`)); err != nil {
		t.Fatal(err)
	}
	first := h
	if err := h.UnmarshalJSON([]byte(`"bbbb"`)); err != nil {
		t.Fatal(err)
	}
	if string(h) != `"bbbb"` || !bytes.Equal(first, make([]byte, len(first))) {
		t.Fatalf("after a second decode the field is %q and the first value %q", []byte(h), []byte(first))
	}
	if err := h.UnmarshalJSON([]byte(`null`)); err != nil || h != nil {
		t.Fatalf("null decoded as %q, %v", []byte(h), err)
	}
}

// A payload naming a secret field twice, once in another case, still loads
// with the later value, as it did: zeroing the replaced value adds no new
// refusal.
func TestParsePayloadStillAcceptsACaseVariantDuplicateSecret(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x77)
	payload := NewEd25519Payload(publicKey, privateKey)
	payload.CreatedAt = canonicalTestTime
	defer payload.ZeroSecrets()
	encoded, err := MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroTestBytes(encoded)
	member := `"private_key": "` + hex.EncodeToString(privateKey) + `"`
	doubled := bytes.Replace(encoded, []byte(member), []byte(member+`, "Private_Key": "`+hex.EncodeToString(privateKey)+`"`), 1)
	parsed, err := ParsePayload(doubled)
	if err != nil {
		t.Fatalf("ParsePayload(case-variant duplicate) error = %v", err)
	}
	defer parsed.ZeroSecrets()
	if !bytes.Equal(parsed.PrivateKey, privateKey) {
		t.Fatal("the duplicate changed the parsed private key")
	}
}

// The encoder is handed the field's own buffer, so zeroing the field clears
// the encoding aplane made; zero clears a decoded field too.
func TestSecretHexZeroClearsTheEncoding(t *testing.T) {
	h := newSecretHex[privateKeyField]([]byte{0xde, 0xad, 0xbe, 0xef})
	encoded, err := h.MarshalJSON()
	if err != nil || string(encoded) != `"deadbeef"` || &encoded[0] != &h[0] {
		t.Fatalf("MarshalJSON = %s, %v; want the field's own buffer", encoded, err)
	}
	h.zero()
	if !bytes.Equal(encoded, make([]byte, len(encoded))) {
		t.Fatalf("zero left %q", encoded)
	}

	var decoded secretHex[recoveryEntropyField]
	if err := decoded.UnmarshalJSON([]byte(`"deadbeef"`)); err != nil {
		t.Fatal(err)
	}
	decoded.zero()
	if !bytes.Equal(decoded, make([]byte, len(decoded))) {
		t.Fatalf("zero left %q", []byte(decoded))
	}
}

// A payload's secrets survive the round trip through the new wire fields,
// and the parsed payload owns buffers apart from the encoded plaintext.
func TestPayloadSecretsRoundTripThroughZeroableWire(t *testing.T) {
	publicKey, privateKey := canonicalEd25519Pair(t, 0x66)
	payload := NewEd25519Payload(publicKey, privateKey)
	payload.CreatedAt = canonicalTestTime
	defer payload.ZeroSecrets()
	encoded, err := MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"private_key": "`+hex.EncodeToString(privateKey)+`"`)) {
		t.Fatalf("encoded payload lacks the private key hex:\n%s", encoded)
	}
	parsed, err := ParsePayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.ZeroSecrets()
	zeroTestBytes(encoded)
	if !bytes.Equal(parsed.PrivateKey, privateKey) {
		t.Fatal("zeroing the plaintext changed the parsed private key")
	}
}
