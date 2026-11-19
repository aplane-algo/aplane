// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"github.com/aplane-algo/aplane/internal/crypto"
)

// secretField names one secret field of the payload JSON, so a secretHex can
// name its field in an error.
type secretField interface{ jsonName() string }

type (
	privateKeyField      struct{}
	recoveryEntropyField struct{}
)

func (privateKeyField) jsonName() string      { return "private_key" }
func (recoveryEntropyField) jsonName() string { return "recovery_entropy" }

// secretHex is a secret field of the payload JSON (private_key,
// recovery_entropy) held as that field's JSON encoding, a quoted hex string,
// in a buffer aplane owns, so the hex text never becomes a Go string and can
// be zeroed once the wire value is used. MarshalJSON hands the buffer to the
// encoder as it is, and UnmarshalJSON keeps a copy of the token the decoder
// read; decode applies the canonical lowercase-hex rule.
type secretHex[F secretField] []byte

// newSecretHex encodes secret as a quoted lowercase hex string, the form
// hex.EncodeToString gives. An empty secret has no encoding, so omitempty
// leaves the field out.
func newSecretHex[F secretField](secret []byte) secretHex[F] {
	if len(secret) == 0 {
		return nil
	}
	out := make(secretHex[F], hex.EncodedLen(len(secret))+2)
	out[0] = '"'
	hex.Encode(out[1:len(out)-1], secret)
	out[len(out)-1] = '"'
	return out
}

func (h secretHex[F]) MarshalJSON() ([]byte, error) {
	if len(h) == 0 {
		return []byte(`""`), nil
	}
	return h, nil
}

// UnmarshalJSON keeps a copy of a string token. A field can be decoded more
// than once (encoding/json matches member names regardless of case), so the
// value it replaces is zeroed first. A value that is not a string is refused
// with the error a string field of payloadWire gave.
func (h *secretHex[F]) UnmarshalJSON(data []byte) error {
	h.zero()
	*h = nil
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	if len(data) < 2 || data[0] != '"' {
		var field F
		return &json.UnmarshalTypeError{
			Value: jsonValueKind(data), Type: reflect.TypeFor[string](),
			Struct: "payloadWire", Field: field.jsonName(),
		}
	}
	*h = append(secretHex[F](nil), data...)
	return nil
}

// jsonValueKind names a JSON value's kind as encoding/json's type errors do.
func jsonValueKind(data []byte) string {
	if len(data) == 0 {
		return "value"
	}
	switch data[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "bool"
	default:
		return "number"
	}
}

// zero clears the encoding.
func (h secretHex[F]) zero() {
	crypto.ZeroBytes(h)
}

// decode returns the bytes the field encodes; an absent or empty field
// decodes to nil. It applies decodeCanonicalHex's rule and errors exactly:
// non-empty lowercase hex. A string the encoder could have written, plain
// ASCII without escapes, is decoded from the buffer in place. Any other
// string, which no canonical payload holds, goes through decodeCanonicalHex
// itself, so its result and errors are unchanged; that path makes a string
// copy.
func (h secretHex[F]) decode() ([]byte, error) {
	if len(h) == 0 {
		return nil, nil
	}
	var f F
	field := f.jsonName()
	text := h[1 : len(h)-1]
	if !plainJSONString(text) {
		var value string
		if err := json.Unmarshal(h, &value); err != nil {
			return nil, incompatibleKeyFormat("invalid %s: %v", field, err)
		}
		return decodeCanonicalHex(field, value)
	}
	if len(text) == 0 {
		return nil, nil
	}
	for _, c := range text {
		if 'A' <= c && c <= 'Z' {
			return nil, incompatibleKeyFormat("%s must be non-empty lowercase hex", field)
		}
	}
	decoded := make([]byte, hex.DecodedLen(len(text)))
	if _, err := hex.Decode(decoded, text); err != nil {
		crypto.ZeroBytes(decoded)
		return nil, incompatibleKeyFormat("invalid %s: %v", field, err)
	}
	return decoded, nil
}

// plainJSONString reports whether the body of a JSON string decodes to
// itself: printable ASCII with no escapes.
func plainJSONString(text []byte) bool {
	for _, c := range text {
		if c < 0x20 || c >= 0x80 || c == '\\' || c == '"' {
			return false
		}
	}
	return true
}
