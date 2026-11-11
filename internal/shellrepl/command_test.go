// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shellrepl

import (
	"strings"
	"testing"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantCmd  string
		wantArgs []string
		wantErr  bool
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
			name:    "quoted note with spaces",
			input:   `send 0.000001 algo from anonymous to whale note="stake with us at RETI, never lose rewards. weget.algo"`,
			wantCmd: "send",
			wantArgs: []string{
				"0.000001",
				"algo",
				"from",
				"anonymous",
				"to",
				"whale",
				"note=stake with us at RETI, never lose rewards. weget.algo",
			},
		},
		{
			name:    "single quoted note with spaces",
			input:   `send 0.000001 algo from anonymous to whale note='stake with us at RETI, never lose rewards. weget.algo'`,
			wantCmd: "send",
			wantArgs: []string{
				"0.000001",
				"algo",
				"from",
				"anonymous",
				"to",
				"whale",
				"note=stake with us at RETI, never lose rewards. weget.algo",
			},
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
		{
			name:     "single quoted string with double quote inside",
			input:    `alias add 'my "account"' ADDR123`,
			wantCmd:  "alias",
			wantArgs: []string{"add", `my "account"`, "ADDR123"},
		},
		{
			name:    "unterminated quote",
			input:   `send 1 algo from "bob`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args, err := ParseCommand(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
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

func TestParseCompletableCommandLine(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		wantParts         []string
		wantTrailingSpace bool
		wantInQuotes      bool
	}{
		{
			name:      "quoted arg with spaces",
			input:     `plugin "mode value" ADDR`,
			wantParts: []string{"plugin", "mode value", "ADDR"},
		},
		{
			name:         "unterminated quoted arg",
			input:        `plugin "mode value`,
			wantParts:    []string{"plugin", "mode value"},
			wantInQuotes: true,
		},
		{
			name:         "unterminated single quoted arg",
			input:        `plugin 'mode value`,
			wantParts:    []string{"plugin", "mode value"},
			wantInQuotes: true,
		},
		{
			name:              "trailing delimiter",
			input:             `plugin "mode value" `,
			wantParts:         []string{"plugin", "mode value"},
			wantTrailingSpace: true,
		},
		{
			name:              "space inside quoted arg is not trailing delimiter",
			input:             `plugin "mode `,
			wantParts:         []string{"plugin", "mode "},
			wantTrailingSpace: false,
			wantInQuotes:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCompletableCommandLine(tt.input)
			if got.trailingSpace != tt.wantTrailingSpace {
				t.Fatalf("trailingSpace = %v, want %v", got.trailingSpace, tt.wantTrailingSpace)
			}
			if got.inQuotes != tt.wantInQuotes {
				t.Fatalf("inQuotes = %v, want %v", got.inQuotes, tt.wantInQuotes)
			}
			if len(got.parts) != len(tt.wantParts) {
				t.Fatalf("parts count = %d, want %d (%v)", len(got.parts), len(tt.wantParts), got.parts)
			}
			for i := range got.parts {
				if got.parts[i] != tt.wantParts[i] {
					t.Fatalf("parts[%d] = %q, want %q", i, got.parts[i], tt.wantParts[i])
				}
			}
		})
	}
}

func TestParseCommandDropsATrailingComment(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"sweep algo to main leaving 1   # Leave 1 ALGO in each", []string{"sweep", "algo", "to", "main", "leaving", "1"}},
		// Only a # standing alone is a comment; #42 is an argument.
		{"myplugin memo #42 confirm", []string{"myplugin", "memo", "#42", "confirm"}},
		{"send 1 algo from a to b #", []string{"send", "1", "algo", "from", "a", "to", "b"}},
		{"# a whole line", nil},
		{"send 1 algo from a to b note=#1", []string{"send", "1", "algo", "from", "a", "to", "b", "note=#1"}},
		{`send 1 algo from a to b note="# not a comment"`, []string{"send", "1", "algo", "from", "a", "to", "b", "note=# not a comment"}},
		{`alias add "#team" ADDR`, []string{"alias", "add", "#team", "ADDR"}},
		{"alias add #team ADDR", []string{"alias", "add", "#team", "ADDR"}},
	}
	for _, tc := range cases {
		command, args, err := ParseCommand(tc.input)
		if err != nil {
			t.Errorf("%q: %v", tc.input, err)
			continue
		}
		var got []string
		if command != "" {
			got = append([]string{command}, args...)
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q parsed as %q, want %q", tc.input, got, tc.want)
		}
	}
}
