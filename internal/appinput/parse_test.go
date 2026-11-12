// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appinput

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestParseByteValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "hex", input: "hex:6869", want: "hi"},
		{name: "hex whitespace", input: "hex: 6869", want: "hi"},
		{name: "base64", input: "b64:aGk=", want: "hi"},
		{name: "base64 whitespace", input: "b64: aGk=", want: "hi"},
		{name: "text", input: "text:hi", want: "hi"},
		{name: "0x compatibility", input: "0x6869", want: "hi"},
		{name: "plain", input: "hi", want: "hi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseByteValue(tt.input)
			if err != nil {
				t.Fatalf("ParseByteValue() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("ParseByteValue() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestParseByteValueRejectsMalformedEncodings(t *testing.T) {
	for _, input := range []string{"hex:xyz", "b64:???", "0xzz"} {
		if _, err := ParseByteValue(input); err == nil {
			t.Fatalf("ParseByteValue(%q) error = nil, want decode error", input)
		}
	}
}

func TestParseOnCompletion(t *testing.T) {
	tests := []struct {
		input string
		want  types.OnCompletion
	}{
		{input: "", want: types.NoOpOC},
		{input: "noop", want: types.NoOpOC},
		{input: "optin", want: types.OptInOC},
		{input: "closeout", want: types.CloseOutOC},
		{input: "clear", want: types.ClearStateOC},
		{input: "update", want: types.UpdateApplicationOC},
		{input: "delete", want: types.DeleteApplicationOC},
	}

	for _, tt := range tests {
		got, err := ParseOnCompletion(tt.input)
		if err != nil {
			t.Fatalf("ParseOnCompletion(%q) error = %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("ParseOnCompletion(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDetectProgramSource(t *testing.T) {
	src := DetectProgramSource("/tmp/approval.teal")
	if src.Compiled {
		t.Fatalf("expected .teal file to be treated as source, got %+v", src)
	}

	bin := DetectProgramSource("/tmp/approval.bin")
	if !bin.Compiled {
		t.Fatalf("expected non-.teal file to be treated as compiled, got %+v", bin)
	}
}

func TestParseByteValueGoalStylePrefixes(t *testing.T) {
	const zeroAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	cases := []struct{ raw, wantHex string }{
		{"int:5", "0000000000000005"},
		{"int:18446744073709551615", "ffffffffffffffff"},
		{"str:withdraw", "7769746864726177"},
		{"text:int:5", "696e743a35"},
		{"addr:" + zeroAddress, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"plain", "706c61696e"},
		{"text:two words: here", "74776f20776f7264733a2068657265"},
		{"two words", "74776f20776f726473"},
	}
	for _, tc := range cases {
		got, err := ParseByteValue(tc.raw)
		if err != nil {
			t.Errorf("ParseByteValue(%q): %v", tc.raw, err)
			continue
		}
		if hex.EncodeToString(got) != tc.wantHex {
			t.Errorf("ParseByteValue(%q) = %x, want %s", tc.raw, got, tc.wantHex)
		}
	}
}

func TestParseEncodedByteValueLeavesBareTextToTheCaller(t *testing.T) {
	for _, raw := range []string{"hex:6869", "b64:aGk=", "text:hi", "str:hi", "int:5", "0x6869", "hex:zz"} {
		if _, encoded, _ := ParseEncodedByteValue(raw); !encoded {
			t.Errorf("ParseEncodedByteValue(%q) reads as bare text", raw)
		}
	}
	for _, raw := range []string{"hi", "", "aGk=", "key:value", "base64:AAAA", "HEX:6869"} {
		if value, encoded, err := ParseEncodedByteValue(raw); encoded || err != nil || value != nil {
			t.Errorf("ParseEncodedByteValue(%q) = %x, %v, %v; want bare text", raw, value, encoded, err)
		}
	}
}

// BytePrefixes is written out by hand for messages; it must name exactly the
// prefixes ParseEncodedByteValue reads.
func TestBytePrefixesMatchTheParser(t *testing.T) {
	samples := map[string]string{
		"hex:":  "6869",
		"b64:":  "aGk=",
		"text:": "hi",
		"str:":  "hi",
		"int:":  "5",
		"addr:": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"0x":    "6869",
	}
	listed := map[string]bool{}
	for _, prefix := range strings.Split(BytePrefixes, ", ") {
		listed[prefix] = true
		sample, ok := samples[prefix]
		if !ok {
			t.Errorf("BytePrefixes lists %q, which has no sample value here", prefix)
			continue
		}
		if _, encoded, err := ParseEncodedByteValue(prefix + sample); !encoded || err != nil {
			t.Errorf("BytePrefixes lists %q, but ParseEncodedByteValue(%q) = %v, %v", prefix, prefix+sample, encoded, err)
		}
	}
	for prefix := range samples {
		if !listed[prefix] {
			t.Errorf("BytePrefixes does not list %q", prefix)
		}
	}
	if _, encoded, _ := ParseEncodedByteValue("utf8:hi"); encoded {
		t.Error(`ParseEncodedByteValue("utf8:hi") reads a made-up prefix as encoded`)
	}

	// A prefix read by the parser but missing from the list: every name of up
	// to four lowercase letters or digits before a colon, and every two
	// characters with none (the form 0x takes), is tried.
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	listedPrefixes := strings.Split(BytePrefixes, ", ")
	try := func(candidate string) {
		for _, prefix := range listedPrefixes {
			if strings.HasPrefix(candidate, prefix) {
				return
			}
		}
		if _, encoded, _ := ParseEncodedByteValue(candidate); encoded {
			t.Errorf("ParseEncodedByteValue reads the prefix %q, which BytePrefixes does not list", candidate)
		}
	}
	for length := 1; length <= 4; length++ {
		name := make([]byte, length)
		for n := 0; n < pow(len(chars), length); n++ {
			for i, rest := 0, n; i < length; i, rest = i+1, rest/len(chars) {
				name[i] = chars[rest%len(chars)]
			}
			try(string(name) + ":")
			if length == 2 {
				try(string(name))
			}
		}
	}
}

func pow(base, exponent int) int {
	result := 1
	for ; exponent > 0; exponent-- {
		result *= base
	}
	return result
}

func TestParseByteValueRefusesUnknownAndMalformedPrefixes(t *testing.T) {
	for _, raw := range []string{
		"int:-1", "int:0x10", "int:18446744073709551616", "int:", "int:5 ",
		"addr:notanaddress", "uint:5", "string:x", "INT:5", "base64:AAAA", "key:value",
		"base-64:AAEC", "u_int:5", "int :5", ":leading", "two words: here", "http://example",
	} {
		if got, err := ParseByteValue(raw); err == nil {
			t.Errorf("ParseByteValue(%q) = %x, want refused", raw, got)
		}
	}
}
