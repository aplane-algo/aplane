// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package termsafe

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// An approval or decision screen shows a client's or a request's text in
// field rows: a name the screen writes, then the value. Every such row is
// drawn by Field or QuotedField, which make it exactly one line of printable
// ASCII no wider than the screen: every other character is escaped as Go
// escapes it (田, \x1b), so the row's width is its length on every
// terminal, and a row too long is cut with a visible "...". No value, whatever
// it holds, can then wrap onto a line of its own and read as another field.
// The name is the caller's own printable ASCII.

// fieldCut marks where a field row's value was cut. It is ASCII, so its width
// is exact on every terminal, where "…" is ambiguous in width.
const fieldCut = "..."

// Field is the field row name and value, the value escaped to printable
// ASCII and cut at its end to fit width columns.
func Field(name, value string, width int) string {
	pieces := asciiPieces(value)
	room := width - len(name)
	if width <= 0 || piecesLen(pieces) <= room {
		return name + strings.Join(pieces, "")
	}
	head, _ := fitPieces(pieces, room-len(fieldCut))
	return clip(name+strings.Join(head, "")+fieldCut, width)
}

// QuotedField is the field row name and value, the value as an ASCII Go
// string literal (strconv.QuoteToASCII), for text the client chose, such as
// a label. A value too long is cut in the middle by cutting the text and
// quoting each part, "head"..."tail", so a cut never splits an escape or
// drops a closing quote. The head, which names the text, gets two thirds of
// the room, and at least its first character, an escape however wide,
// where the room holds it.
func QuotedField(name, value string, width int) string {
	pieces := asciiPieces(value)
	room := width - len(name)
	if width <= 0 || piecesLen(pieces)+2 <= room {
		return name + `"` + strings.Join(pieces, "") + `"`
	}
	// Two quoted parts and the mark between them.
	text := room - 2*len(`""`) - len(fieldCut)
	head, used := fitPieces(pieces, text*2/3)
	if len(head) == 0 && len(pieces) > 0 && len(pieces[0]) <= text {
		head, used = pieces[:1], len(pieces[0])
	}
	var tail []string
	left := text - used
	for i := len(pieces) - 1; i >= len(head) && len(pieces[i]) <= left; i-- {
		tail = append([]string{pieces[i]}, tail...)
		left -= len(pieces[i])
	}
	return clip(name+`"`+strings.Join(head, "")+`"`+fieldCut+`"`+strings.Join(tail, "")+`"`, width)
}

// asciiPieces is s escaped to printable ASCII as in a Go string literal, one
// piece for each character or invalid byte, so a cut between pieces never
// splits an escape.
func asciiPieces(s string) []string {
	var pieces []string
	for i := 0; i < len(s); {
		_, size := utf8.DecodeRuneInString(s[i:])
		quoted := strconv.QuoteToASCII(s[i : i+size])
		pieces = append(pieces, quoted[1:len(quoted)-1])
		i += size
	}
	return pieces
}

func piecesLen(pieces []string) int {
	n := 0
	for _, piece := range pieces {
		n += len(piece)
	}
	return n
}

// fitPieces is the most of pieces, from the first, that fit room bytes, and
// their length.
func fitPieces(pieces []string, room int) ([]string, int) {
	used := 0
	for i, piece := range pieces {
		if used+len(piece) > room {
			return pieces[:i], used
		}
		used += len(piece)
	}
	return pieces, used
}

// clip cuts an ASCII row to width bytes, for a width too narrow for even its
// name and the cut mark.
func clip(row string, width int) string {
	if len(row) > width {
		return row[:max(width, 0)]
	}
	return row
}

// resultLabelWidth bounds a label a result line names. Such a line runs on
// with the screen's text and can wrap at the label's spaces; cut to this,
// the label is too short to carry a fingerprint onto a line it starts.
const resultLabelWidth = 32

// ResultLabel is a client's label as a line reporting a decision names it:
// an ASCII Go string literal cut in the middle to resultLabelWidth columns.
func ResultLabel(label string) string {
	return QuotedField("", label, resultLabelWidth)
}
