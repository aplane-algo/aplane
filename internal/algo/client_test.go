// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package algo

import (
	"testing"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantCmd  string
		wantArgs []string
	}{
		{
			name:     "simple command",
			input:    "status",
			wantCmd:  "status",
			wantArgs: nil,
		},
		{
			name:     "command with args",
			input:    "send 1 algo from alice to bob",
			wantCmd:  "send",
			wantArgs: []string{"1", "algo", "from", "alice", "to", "bob"},
		},
		{
			name:     "command with quoted string",
			input:    `send 1 algo from alice to bob note="hello world"`,
			wantCmd:  "send",
			wantArgs: []string{"1", "algo", "from", "alice", "to", "bob", "note=hello world"},
		},
		{
			name:     "empty input",
			input:    "",
			wantCmd:  "",
			wantArgs: nil,
		},
		{
			name:     "whitespace only",
			input:    "   \t  ",
			wantCmd:  "",
			wantArgs: nil,
		},
		{
			name:     "leading whitespace",
			input:    "  status",
			wantCmd:  "status",
			wantArgs: nil,
		},
		{
			name:     "multiple spaces between args",
			input:    "send   1    algo",
			wantCmd:  "send",
			wantArgs: []string{"1", "algo"},
		},
		{
			name:     "tabs as separators",
			input:    "send\t1\talgo",
			wantCmd:  "send",
			wantArgs: []string{"1", "algo"},
		},
		{
			name:     "quoted string with spaces",
			input:    `alias add "my account" ADDR123`,
			wantCmd:  "alias",
			wantArgs: []string{"add", "my account", "ADDR123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args := ParseCommand(tt.input)
			if cmd != tt.wantCmd {
				t.Errorf("ParseCommand() cmd = %v, want %v", cmd, tt.wantCmd)
			}
			if len(args) != len(tt.wantArgs) {
				t.Errorf("ParseCommand() args count = %v, want %v", len(args), len(tt.wantArgs))
				return
			}
			for i, arg := range args {
				if arg != tt.wantArgs[i] {
					t.Errorf("ParseCommand() args[%d] = %v, want %v", i, arg, tt.wantArgs[i])
				}
			}
		})
	}
}

func TestConvertTokenAmountToBaseUnits(t *testing.T) {
	tests := []struct {
		name     string
		amount   string
		decimals uint64
		want     uint64
		wantErr  bool
	}{
		{
			name:     "whole number with 6 decimals",
			amount:   "1",
			decimals: 6,
			want:     1000000,
			wantErr:  false,
		},
		{
			name:     "decimal amount with 6 decimals",
			amount:   "1.5",
			decimals: 6,
			want:     1500000,
			wantErr:  false,
		},
		{
			name:     "zero amount",
			amount:   "0",
			decimals: 6,
			want:     0,
			wantErr:  false,
		},
		{
			name:     "small decimal",
			amount:   "0.000001",
			decimals: 6,
			want:     1,
			wantErr:  false,
		},
		{
			name:     "0 decimals asset",
			amount:   "100",
			decimals: 0,
			want:     100,
			wantErr:  false,
		},
		{
			name:     "large amount",
			amount:   "1000000",
			decimals: 6,
			want:     1000000000000,
			wantErr:  false,
		},
		{
			name:     "invalid amount string",
			amount:   "abc",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "too many decimal places",
			amount:   "1.0000001",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "negative amount",
			amount:   "-1",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertTokenAmountToBaseUnits(tt.amount, tt.decimals)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertTokenAmountToBaseUnits() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ConvertTokenAmountToBaseUnits() = %v, want %v", got, tt.want)
			}
		})
	}
}
