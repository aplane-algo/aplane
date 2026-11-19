// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
)

// secretHex is a secret field of the payload JSON (private_key,
// recovery_entropy) held as that field's JSON encoding, a quoted hex string,
// in a buffer aplane owns, so the hex text never becomes a Go string and can
// be zeroed once the wire value is used. MarshalJSON hands the buffer to the
// encoder as it is, and UnmarshalJSON keeps a copy of the token the decoder
// read; decode applies the canonical lowercase-hex rule.
type secretHex []byte

// newSecretHex encodes secret as a quoted lowercase hex string, the form
// hex.EncodeToString gives. An empty secret has no encoding, so omitempty
// leaves the field out.
func newSecretHex(secret []byte) secretHex {
	if len(secret) == 0 {
		return nil
	}
	out := make(secretHex, hex.EncodedLen(len(secret))+2)
	out[0] = '"'
	hex.Encode(out[1:len(out)-1], secret)
	out[len(out)-1] = '"'
	return out
}

func (h secretHex) MarshalJSON() ([]byte, error) {
	if len(h) == 0 {
		return []byte(`""`), nil
	}
	return h, nil
}

func (h *secretHex) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*h = nil
		return nil
	}
	if len(data) < 2 || data[0] != '"' {
		return fmt.Errorf("expected a JSON string")
	}
	*h = append(secretHex(nil), data...)
	return nil
}

// zero clears the encoding.
func (h secretHex) zero() {
	crypto.ZeroBytes(h)
}

// decode returns the bytes the field encodes; an absent or empty field
// decodes to nil. It applies decodeCanonicalHex's rule and errors exactly:
// non-empty lowercase hex. A string the encoder could have written, plain
// ASCII without escapes, is decoded from the buffer in place. Any other
// string, which no canonical payload holds, goes through decodeCanonicalHex
// itself, so its result and errors are unchanged; that path makes a string
// copy.
func (h secretHex) decode(field string) ([]byte, error) {
	if len(h) == 0 {
		return nil, nil
	}
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
