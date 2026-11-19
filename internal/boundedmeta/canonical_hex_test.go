// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// stringCanonicalHex is DecodeCanonicalHex as it was before the rule moved to
// bytes, kept to check that the move changed nothing.
func stringCanonicalHex(field, value string, minSize, maxSize int) ([]byte, error) {
	if value == "" || value != strings.ToLower(value) {
		return nil, fmt.Errorf("%s must be non-empty lowercase hex", field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	if maxSize > 0 && (len(decoded) < minSize || len(decoded) > maxSize) {
		if minSize == maxSize {
			return nil, fmt.Errorf("%s length %d invalid (expected %d bytes)", field, len(decoded), maxSize)
		}
		return nil, fmt.Errorf("%s length %d invalid (expected %d-%d bytes)", field, len(decoded), minSize, maxSize)
	}
	return decoded, nil
}

// Both forms of the canonical-hex rule accept, decode and refuse exactly as
// the string rule did, with the same errors, across hex, case, length, prefix,
// non-ASCII and invalid UTF-8 input.
func TestCanonicalHexFormsMatchTheStringRule(t *testing.T) {
	values := []string{
		"", "00", "0a1b", "deadbeef", "DEADBEEF", "deadBeef", "0", "abc", "0x0a", " 0a", "0a ",
		"0g", "zz", "é0", "0É", "\u212a0", "\u01300a", "\ufffd", "0a\ufffd", "\xff", "0a\xff",
		"\xef\xbf", "\xef\xbf\x00", "\xc3", "ÿÿ", strings.Repeat("ab", 40),
	}
	// Every string of up to four pieces from an alphabet of hex digits,
	// uppercase, non-hex, non-ASCII and invalid UTF-8.
	alphabet := []string{"0", "9", "a", "f", "A", "F", "g", "x", " ", "é", "É", "\xff", "\xc3", "\ufffd", "\u212a"}
	level := []string{""}
	for range 4 {
		var next []string
		for _, prefix := range level {
			for _, piece := range alphabet {
				next = append(next, prefix+piece)
			}
		}
		values = append(values, next...)
		level = next
	}
	for _, value := range values {
		for _, bounds := range [][2]int{{0, 0}, {2, 2}, {1, 4}} {
			want, wantErr := stringCanonicalHex("field", value, bounds[0], bounds[1])
			got, gotErr := DecodeCanonicalHex("field", value, bounds[0], bounds[1])
			gotBytes, gotBytesErr := DecodeCanonicalHexBytes("field", []byte(value), bounds[0], bounds[1])
			for form, result := range map[string]struct {
				out []byte
				err error
			}{"string": {got, gotErr}, "bytes": {gotBytes, gotBytesErr}} {
				if !bytes.Equal(result.out, want) || fmt.Sprint(result.err) != fmt.Sprint(wantErr) {
					t.Fatalf("%s form on %q %v = %x, %v; want %x, %v", form, value, bounds, result.out, result.err, want, wantErr)
				}
			}
		}
	}
}

// The bytes form leaves its input alone and returns a buffer of its own.
func TestDecodeCanonicalHexBytesOnlyReadsItsInput(t *testing.T) {
	value := []byte("deadbeef")
	decoded, err := DecodeCanonicalHexBytes("field", value, 0, 0)
	if err != nil || !bytes.Equal(decoded, []byte{0xde, 0xad, 0xbe, 0xef}) || string(value) != "deadbeef" {
		t.Fatalf("decode = %x, %v; input now %q", decoded, err, value)
	}
}
