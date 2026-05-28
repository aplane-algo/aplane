// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"bytes"
	"testing"
)

func TestParseByteValue(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		allowBareText bool
		want          []byte
		wantErr       bool
	}{
		{name: "hex prefix", input: "hex:68656c6c6f", want: []byte("hello")},
		{name: "base64 prefix", input: "b64:aGVsbG8=", want: []byte("hello")},
		{name: "text prefix", input: "text:hello", want: []byte("hello")},
		{name: "0x compatibility", input: "0x68656c6c6f", want: []byte("hello")},
		{name: "bare text allowed", input: "hello", allowBareText: true, want: []byte("hello")},
		{name: "bare text rejected", input: "hello", wantErr: true},
		{name: "invalid hex", input: "hex:xyz", wantErr: true},
		{name: "invalid b64", input: "b64:???", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseByteValue(tt.input, tt.allowBareText)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseByteValue() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("ParseByteValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
