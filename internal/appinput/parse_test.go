// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appinput

import (
	"encoding/hex"
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
		{"two words: here", "74776f20776f7264733a2068657265"},
		{":leading", "3a6c656164696e67"},
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

func TestParseByteValueRefusesUnknownAndMalformedPrefixes(t *testing.T) {
	for _, raw := range []string{
		"int:-1", "int:0x10", "int:18446744073709551616", "int:", "int:5 ",
		"addr:notanaddress", "uint:5", "string:x", "INT:5", "base64:AAAA", "key:value",
	} {
		if got, err := ParseByteValue(raw); err == nil {
			t.Errorf("ParseByteValue(%q) = %x, want refused", raw, got)
		}
	}
}
