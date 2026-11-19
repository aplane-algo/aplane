// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bytes"
	"fmt"
	"reflect"
	"unicode/utf16"
	"unicode/utf8"
)

// SensitiveBytes carries a JSON string as mutable bytes after unmarshal so
// handlers can zero passphrase material after use.
//
// Contract: SensitiveBytes carries UTF-8 text only (passphrases, template
// YAML). MarshalJSON emits the bytes as a JSON string, so non-UTF-8 input
// would be corrupted to U+FFFD replacement runes on the peer. Binary key
// material must not use this type; give it a distinct base64-encoded type
// instead.
type SensitiveBytes []byte

func NewSensitiveBytes(s string) SensitiveBytes {
	return SensitiveBytes([]byte(s))
}

func (s SensitiveBytes) Clone() []byte {
	if len(s) == 0 {
		return nil
	}
	out := make([]byte, len(s))
	copy(out, s)
	return out
}

func (s SensitiveBytes) Zero() {
	for i := range s {
		s[i] = 0
	}
}

// ZeroSensitive zeroes every SensitiveBytes value reachable from v through
// pointers, interfaces, exported struct fields, arrays, slices and map values.
// It is for a value that is being dropped, such as a message whose decode
// failed after filling some of its fields.
func ZeroSensitive(v any) {
	zeroSensitiveValue(reflect.ValueOf(v))
}

var sensitiveBytesType = reflect.TypeFor[SensitiveBytes]()

func zeroSensitiveValue(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			zeroSensitiveValue(v.Elem())
		}
	case reflect.Struct:
		t := v.Type()
		for i := range v.NumField() {
			if t.Field(i).IsExported() {
				zeroSensitiveValue(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.Type() == sensitiveBytesType {
			clear(v.Bytes())
			return
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := range v.Len() {
			zeroSensitiveValue(v.Index(i))
		}
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := range v.Len() {
			zeroSensitiveValue(v.Index(i))
		}
	case reflect.Map:
		for iter := v.MapRange(); iter.Next(); {
			zeroSensitiveValue(iter.Value())
		}
	}
}

func (s SensitiveBytes) String() string {
	return "<redacted>"
}

func (s SensitiveBytes) GoString() string {
	return "protocol.SensitiveBytes(<redacted>)"
}

// MarshalJSON writes the bytes as a JSON string straight into one buffer of
// the exact size: no intermediate string, no pooled encoder buffer, and no
// HTML escaping. Otherwise it escapes as encoding/json does: invalid UTF-8
// becomes U+FFFD, and control characters, quotes, backslashes, U+2028 and
// U+2029 are escaped. The calling encoder copies the returned buffer into
// its own and drops it unzeroed; that copy is the residue this cannot avoid.
func (s SensitiveBytes) MarshalJSON() ([]byte, error) {
	size := 2
	for i := 0; i < len(s); {
		escape, consumed := jsonStringEscape(s, i)
		if escape == "" {
			size += consumed
		} else {
			size += len(escape)
		}
		i += consumed
	}
	out := make([]byte, 0, size)
	out = append(out, '"')
	for i := 0; i < len(s); {
		escape, consumed := jsonStringEscape(s, i)
		if escape == "" {
			out = append(out, s[i:i+consumed]...)
		} else {
			out = append(out, escape...)
		}
		i += consumed
	}
	return append(out, '"'), nil
}

// jsonControlEscapes holds the JSON escape for each control character.
var jsonControlEscapes = func() [0x20]string {
	var escapes [0x20]string
	const hex = "0123456789abcdef"
	for c := range escapes {
		escapes[c] = `\u00` + string(hex[c>>4]) + string(hex[c&0xF])
	}
	escapes['\b'] = `\b`
	escapes['\f'] = `\f`
	escapes['\n'] = `\n`
	escapes['\r'] = `\r`
	escapes['\t'] = `\t`
	return escapes
}()

// jsonStringEscape reports how the rune at s[i:] is written inside a JSON
// string: consumed is the number of input bytes it takes, and escape is the
// text written in their place, or "" when they are written as they are.
func jsonStringEscape(s []byte, i int) (escape string, consumed int) {
	c := s[i]
	if c < utf8.RuneSelf {
		switch {
		case c < 0x20:
			return jsonControlEscapes[c], 1
		case c == '"':
			return `\"`, 1
		case c == '\\':
			return `\\`, 1
		default:
			return "", 1
		}
	}
	r, size := utf8.DecodeRune(s[i:])
	switch {
	case r == utf8.RuneError && size == 1:
		return `\ufffd`, 1
	case r == '\u2028':
		return `\u2028`, size
	case r == '\u2029':
		return `\u2029`, size
	default:
		return "", size
	}
}

func (s *SensitiveBytes) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*s = nil
		return nil
	}
	value, err := unmarshalJSONStringBytes(data)
	if err != nil {
		return err
	}
	*s = SensitiveBytes(value)
	return nil
}

func unmarshalJSONStringBytes(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, fmt.Errorf("expected JSON string")
	}
	// Decoding never lengthens a string, so out never grows past this
	// capacity and leaves no outgrown copy behind.
	return decodeJSONStringBytes(make([]byte, 0, len(data)-2), data)
}

// decodeJSONStringBytes appends the decoded contents of the JSON string data
// to out. On error it zeroes all of out, up to its capacity, so a value cut
// off by a bad escape leaves no partial copy.
func decodeJSONStringBytes(out, data []byte) (_ []byte, err error) {
	defer func() {
		if err != nil {
			SensitiveBytes(out[:cap(out)]).Zero()
		}
	}()
	end := len(data) - 1
	for i := 1; i < end; i++ {
		c := data[i]
		if c == '"' {
			return nil, fmt.Errorf("invalid unescaped quote in JSON string")
		}
		if c < 0x20 {
			return nil, fmt.Errorf("invalid control character in JSON string")
		}
		if c != '\\' {
			out = append(out, c)
			continue
		}

		i++
		if i >= end {
			return nil, fmt.Errorf("invalid escape in JSON string")
		}
		switch data[i] {
		case '"', '\\', '/':
			out = append(out, data[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, err := parseJSONUnicodeEscape(data[i+1:], end-i-1)
			if err != nil {
				return nil, err
			}
			i += 4
			if utf16.IsSurrogate(r) {
				if r < 0xD800 || r > 0xDBFF {
					return nil, fmt.Errorf("invalid low surrogate without high surrogate")
				}
				if i+6 >= end || data[i+1] != '\\' || data[i+2] != 'u' {
					return nil, fmt.Errorf("missing low surrogate")
				}
				low, err := parseJSONUnicodeEscape(data[i+3:], end-i-3)
				if err != nil {
					return nil, err
				}
				if low < 0xDC00 || low > 0xDFFF {
					return nil, fmt.Errorf("invalid low surrogate")
				}
				r = utf16.DecodeRune(r, low)
				i += 6
			}
			out = utf8.AppendRune(out, r)
		default:
			return nil, fmt.Errorf("invalid escape in JSON string")
		}
	}
	return out, nil
}

func parseJSONUnicodeEscape(data []byte, available int) (rune, error) {
	if available < 4 || len(data) < 4 {
		return 0, fmt.Errorf("short unicode escape in JSON string")
	}
	var r rune
	for i := 0; i < 4; i++ {
		v, ok := hexValue(data[i])
		if !ok {
			return 0, fmt.Errorf("invalid unicode escape in JSON string")
		}
		r = r<<4 | rune(v)
	}
	return r, nil
}

func hexValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}
