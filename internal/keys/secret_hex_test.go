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
		F secretHex `json:"f,omitempty"`
	}
	type asString struct {
		F string `json:"f,omitempty"`
	}
	for _, secret := range [][]byte{nil, {0x00}, {0xab, 0xcd}, bytes.Repeat([]byte{0x5a, 0xa5}, 1153)} {
		got, err := json.MarshalIndent(asBytes{newSecretHex(secret)}, "", "  ")
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
			F secretHex `json:"f"`
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
		got, gotErr := asBytes.F.decode("private_key")
		want, wantErr := decodeCanonicalHex("private_key", asString.F)
		if !bytes.Equal(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
			t.Fatalf("%s: decode = %x, %v; want %x, %v", token, got, gotErr, want, wantErr)
		}
	}
}

// A secretHex field refuses a value that is not a string, as the string
// field did.
func TestSecretHexRefusesNonStrings(t *testing.T) {
	for _, value := range []string{`12`, `true`, `{}`, `[]`} {
		var wire struct {
			F secretHex `json:"f"`
		}
		if err := json.Unmarshal([]byte(`{"f":`+value+`}`), &wire); err == nil {
			t.Fatalf("%s decoded as %q", value, wire.F)
		}
	}
}

// The encoder is handed the field's own buffer, so zeroing the field clears
// the encoding aplane made; zero clears a decoded field too.
func TestSecretHexZeroClearsTheEncoding(t *testing.T) {
	h := newSecretHex([]byte{0xde, 0xad, 0xbe, 0xef})
	encoded, err := h.MarshalJSON()
	if err != nil || string(encoded) != `"deadbeef"` || &encoded[0] != &h[0] {
		t.Fatalf("MarshalJSON = %s, %v; want the field's own buffer", encoded, err)
	}
	h.zero()
	if !bytes.Equal(encoded, make([]byte, len(encoded))) {
		t.Fatalf("zero left %q", encoded)
	}

	var decoded secretHex
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
