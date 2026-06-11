// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func (s SensitiveBytes) String() string {
	return "<redacted>"
}

func (s SensitiveBytes) GoString() string {
	return "protocol.SensitiveBytes(<redacted>)"
}

func (s SensitiveBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(string([]byte(s)))
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
	out := make([]byte, 0, len(data)-2)
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
