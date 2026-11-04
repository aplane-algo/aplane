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

// Line escapes s for printing on one line.
func Line(s string) string { return escapeNonPrinting(s, false) }

// Lines escapes s for printing, keeping newlines and tabs.
func Lines(s string) string { return escapeNonPrinting(s, true) }

func escapeNonPrinting(s string, keepLines bool) string {
	if printsAsIs(s, keepLines) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case printsAs(r, keepLines):
			b.WriteRune(r)
		default:
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		}
		i += size
	}
	return b.String()
}

func printsAsIs(s string, keepLines bool) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if !printsAs(r, keepLines) {
			return false
		}
		i += size
	}
	return true
}

// printsAs reports whether r prints as itself: a printable character, or a
// newline or tab when lines are kept.
func printsAs(r rune, keepLines bool) bool {
	return unicode.IsPrint(r) || (keepLines && (r == '\n' || r == '\t'))
}
