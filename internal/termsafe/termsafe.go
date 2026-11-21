// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package termsafe makes untrusted text safe to print on a terminal.
//
// Text this program did not write, such as a file name from the operator's
// disk or a plugin's log line, may hold terminal control sequences: printed as
// is, a name holding ESC [2J clears the screen, and bidirectional controls can
// make one name look like another. These functions show every non-printing
// character and every invalid UTF-8 byte as a Go escape (\x1b, \u202e, \xff)
// instead, so it is seen rather than acted on. Only the display changes; the
// program keeps and uses the original text.
package termsafe

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PrintableASCII reports whether every byte of s is printable ASCII, 0x20 to
// 0x7E: text that prints as itself and whose width is its length on every
// terminal.
func PrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Line escapes s for printing on one line.
func Line(s string) string { return escapeNonPrinting(s, false, false) }

// Lines escapes s for printing, keeping newlines and tabs.
func Lines(s string) string { return escapeNonPrinting(s, true, false) }

// Screen escapes a whole rendered screen as Lines does, but keeps its SGR
// sequences (ESC [ parameters m), the only control sequences a styled
// rendering writes. It is the last pass before a screen reaches the
// terminal, so text a view forgot to escape cannot clear the screen, move the
// cursor or set the title. An SGR sequence inside such text survives it, and
// the escapes change the text's width after layout, so a view still escapes
// outside text with Line or Lines before it styles and lays it out.
func Screen(s string) string { return escapeNonPrinting(s, true, true) }

func escapeNonPrinting(s string, keepLines, keepSGR bool) string {
	var b strings.Builder
	copied := 0 // s[:copied] is in b
	for i := 0; i < len(s); {
		if keepSGR {
			if n := sgrLen(s[i:]); n > 0 {
				i += n
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		invalid := r == utf8.RuneError && size == 1
		if !invalid && printsAs(r, keepLines) {
			i += size
			continue
		}
		b.WriteString(s[copied:i])
		if invalid {
			fmt.Fprintf(&b, `\x%02x`, s[i])
		} else {
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		}
		i += size
		copied = i
	}
	if copied == 0 {
		return s
	}
	b.WriteString(s[copied:])
	return b.String()
}

// sgrLen is the length of the SGR sequence s starts with, or 0.
func sgrLen(s string) int {
	if len(s) < 3 || s[0] != '\x1b' || s[1] != '[' {
		return 0
	}
	for i := 2; i < len(s); i++ {
		switch c := s[i]; {
		case c == 'm':
			return i + 1
		case c >= '0' && c <= '9', c == ';', c == ':':
		default:
			return 0
		}
	}
	return 0
}

// printsAs reports whether r prints as itself: a printable character, or a
// newline or tab when lines are kept.
func printsAs(r rune, keepLines bool) bool {
	return unicode.IsPrint(r) || (keepLines && (r == '\n' || r == '\t'))
}
