// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appinput

import (
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
