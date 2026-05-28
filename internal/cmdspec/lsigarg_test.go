// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"bytes"
	"testing"
)

func TestParseLsigArg(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantName  string
		wantValue []byte
		wantErr   bool
	}{
		{
			name:      "string value",
			token:     "arg:preimage=hello",
			wantName:  "preimage",
			wantValue: []byte("hello"),
		},
		{
			name:      "hex value",
			token:     "arg:preimage=0x68656c6c6f",
			wantName:  "preimage",
			wantValue: []byte("hello"),
		},
		{
			name:      "hex value that looks like a word",
			token:     "arg:preimage=0xCAFE",
			wantName:  "preimage",
			wantValue: []byte{0xca, 0xfe},
		},
		{
			name:      "hex prefix value",
			token:     "arg:preimage=hex:68656c6c6f",
			wantName:  "preimage",
			wantValue: []byte("hello"),
		},
		{
			name:      "base64 prefix value",
			token:     "arg:preimage=b64:aGVsbG8=",
			wantName:  "preimage",
			wantValue: []byte("hello"),
		},
		{
			name:      "text prefix value",
			token:     "arg:preimage=text:hello",
			wantName:  "preimage",
			wantValue: []byte("hello"),
		},
		{
			name:      "string that looks like hex",
			token:     "arg:preimage=cafe",
			wantName:  "preimage",
			wantValue: []byte("cafe"),
		},
		{
			name:      "empty value",
			token:     "arg:preimage=",
			wantName:  "preimage",
			wantValue: []byte(""),
		},
		{
			name:      "empty hex value",
			token:     "arg:preimage=0x",
			wantName:  "preimage",
			wantValue: []byte(""),
		},
		{
			name:    "missing equals",
			token:   "arg:preimage",
			wantErr: true,
		},
		{
			name:    "invalid hex",
			token:   "arg:preimage=0xxyz",
			wantErr: true,
		},
		{
			name:    "invalid prefixed hex",
			token:   "arg:preimage=hex:xyz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, value, err := ParseLsigArg(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLsigArg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if name != tt.wantName {
					t.Errorf("name = %v, want %v", name, tt.wantName)
				}
				if !bytes.Equal(value, tt.wantValue) {
					t.Errorf("value = %v, want %v", value, tt.wantValue)
				}
			}
		})
	}
}
