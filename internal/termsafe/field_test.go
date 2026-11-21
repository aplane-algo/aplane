// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package termsafe

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// fieldPieces are what a client or a request could put in a field's value:
// line breaks, terminal controls, invalid bytes, quotes and backslashes,
// lookalike field names, wide characters and clusters the width library
// counts as three columns or more.
var fieldPieces = []string{
	"a", "Z", " ", `"`, `\`, "\n", "\r", "\t", "\x1b[2J", "\u009b31m", "\u202e", "\u200b", "\xff", "\xc3",
	"Fingerprint: ", "Address: ", "SHA256:", "...", "田", "\U0001f600", "\U0001f44d\U0001f3fd",
	"⸻", "⸺", "田ःः", "é",
}

// Every field row is exactly one line of printable ASCII no wider than its
// width, whatever its value holds; a quoted row keeps its quotes, and a row
// that fits shows its value whole.
func TestFieldRowsAreOneASCIILine(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for range 50000 {
		var b strings.Builder
		for range r.Intn(40) {
			b.WriteString(fieldPieces[r.Intn(len(fieldPieces))])
		}
		value, name, width := b.String(), "Label: ", 7+r.Intn(200)
		for kind, row := range map[string]string{"Field": Field(name, value, width), "QuotedField": QuotedField(name, value, width)} {
			if len(row) > width || !strings.HasPrefix(row, name) || strings.ContainsFunc(row, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
				t.Fatalf("%s(%q, %d) = %q: not one ASCII row of at most %d columns", kind, value, width, row, width)
			}
		}
		quoted := QuotedField(name, value, width)
		if width >= len(name)+len(`""...""`) && (!strings.HasPrefix(quoted, name+`"`) || !strings.HasSuffix(quoted, `"`)) {
			t.Fatalf("QuotedField(%q, %d) = %q: loses a quote", value, width, quoted)
		}
		if whole := name + strconv.QuoteToASCII(value); len(whole) <= width && quoted != whole {
			t.Fatalf("QuotedField(%q, %d) = %q, want it whole, %q", value, width, quoted, whole)
		}
	}
}

// A cut is between whole escapes: the quoted parts are each a Go string
// literal of a run of the value, so none splits an escape or ends early.
func TestQuotedFieldCutsBetweenEscapes(t *testing.T) {
	value := `ops-laptop-of-the-ops-team-\\" Address: 10.9.8.7:51234 ` + "田中\xff\u202e" + strings.Repeat("x", 40)
	for width := 20; width < 120; width++ {
		row := QuotedField("Label: ", value, width)
		literal := strings.TrimPrefix(row, "Label: ")
		head, tail, cut := strings.Cut(literal, `"..."`)
		if !cut {
			if literal != strconv.QuoteToASCII(value) {
				t.Fatalf("width %d: %q is neither whole nor cut", width, row)
			}
			continue
		}
		for _, part := range []string{head + `"`, `"` + tail} {
			if unquoted, err := strconv.Unquote(part); err != nil || !strings.Contains(value, unquoted) {
				t.Fatalf("width %d: part %q of %q is not a run of the value (%v)", width, part, row, err)
			}
		}
	}
}
