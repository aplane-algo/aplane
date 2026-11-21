// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package termsafe

import (
	"testing"
	"unicode/utf8"
)

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

func TestScreenKeepsStylingOnly(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is unchanged", "a\n\tb", "a\n\tb"},
		{"SGR styling is kept", "\x1b[1;38;5;12mtitle\x1b[0m\n\x1b[38:2:1:2:3mx\x1b[m", "\x1b[1;38;5;12mtitle\x1b[0m\n\x1b[38:2:1:2:3mx\x1b[m"},
		{"clear screen", "a\x1b[2Jb", `a\x1b[2Jb`},
		{"window title", "a\x1b]0;x\x07b", `a\x1b]0;x\ab`},
		{"cursor movement", "\x1b[3;1H", `\x1b[3;1H`},
		{"unterminated SGR", "a\x1b[1", `a\x1b[1`},
		{"C1 control sequence introducer", "a\u009b2Jb", `a\u009b2Jb`},
		{"bidirectional and format controls", "a\u202eb\u200bc", `a\u202eb\u200bc`},
		{"carriage return", "a\rb", `a\rb`},
		{"invalid UTF-8", "a\xffb", `a\xffb`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Screen(tt.in); got != tt.want {
				t.Errorf("Screen(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Printable holds exactly for text Line leaves as it is: printable Unicode,
// CJK included, and no control, format or other non-printing character or
// invalid byte.
func TestPrintable(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want bool
	}{
		{"", true}, {"ops laptop", true}, {"田中のノートPC", true}, {"phone 😀", true},
		{"a\nb", false}, {"a\tb", false}, {"a\x1b[2Jb", false}, {"a\x7fb", false},
		{"a\u0085b", false}, {"a\u202eb", false}, {"a\u200bb", false}, {"a\u00a0b", false}, {"a\xffb", false},
	} {
		if got := Printable(tc.s); got != tc.want {
			t.Errorf("Printable(%q) = %v, want %v", tc.s, got, tc.want)
		}
		if got := Line(tc.s) == tc.s && utf8.ValidString(tc.s); got != tc.want {
			t.Errorf("Line(%q) leaves it as it is: %v, want %v", tc.s, got, tc.want)
		}
	}
}
