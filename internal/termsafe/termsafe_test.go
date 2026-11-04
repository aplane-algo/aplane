// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package termsafe

import "testing"

func TestEscaping(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		line  string
		lines string
	}{
		{"plain text is unchanged", "héllo wörld", "héllo wörld", "héllo wörld"},
		{"escape sequence", "a\x1b[2Jb", `a\x1b[2Jb`, `a\x1b[2Jb`},
		{"bidirectional control", "a\u202eb", "a\\u202eb", "a\\u202eb"},
		{"invalid UTF-8", "a\xffb", `a\xffb`, `a\xffb`},
		{"carriage return", "a\rb", `a\rb`, `a\rb`},
		{"newline and tab", "a\n\tb", `a\n\tb`, "a\n\tb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Line(tt.in); got != tt.line {
				t.Errorf("Line(%q) = %q, want %q", tt.in, got, tt.line)
			}
			if got := Lines(tt.in); got != tt.lines {
				t.Errorf("Lines(%q) = %q, want %q", tt.in, got, tt.lines)
			}
		})
	}
}
