// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"bytes"
	"errors"
)

// A policy file an operator writes may carry // line comments and /* block */
// comments outside strings. They are a convenience of the producer tools
// only: the node stores and verifies exact bytes and accepts strict JSON, so
// every producer path removes comments before a document is sent to the node
// (StripComments) and the stored document never contains them.

var errUnterminatedComment = errors.New("unterminated /* comment")

// StripComments removes comments from data and returns the document the node
// receives. Text with no comment is returned unchanged, byte for byte. A
// comment on one line becomes a single space, so the tokens around it stay
// separate: "fa/* x */lse" is not turned into "false". A comment spanning
// lines keeps its newlines. A line that then holds only whitespace
// disappears, and trailing whitespace left where a comment was removed is
// dropped, so a stored document does not keep blank lines where its notes
// were.
func StripComments(data []byte) ([]byte, error) {
	spans, err := commentSpans(data)
	if err != nil {
		return nil, err
	}
	if len(spans) == 0 {
		return data, nil
	}
	// Replace the comments, keeping their newlines so lines still line up
	// with the original, then rebuild line by line: a line a comment
	// touched is trimmed on the right and dropped when nothing is left.
	deleted := deleteSpans(data, spans)
	touched := touchedLines(data, spans)
	var out bytes.Buffer
	out.Grow(len(data))
	line := 0
	for start := 0; start <= len(deleted); line++ {
		end := bytes.IndexByte(deleted[start:], '\n')
		last := end < 0
		if last {
			end = len(deleted)
		} else {
			end += start
		}
		text := deleted[start:end]
		if touched[line] {
			text = bytes.TrimRight(text, " \t\r")
			if len(text) == 0 {
				if last {
					break
				}
				start = end + 1
				continue
			}
		}
		out.Write(text)
		if last {
			break
		}
		out.WriteByte('\n')
		start = end + 1
	}
	return out.Bytes(), nil
}

// BlankComments replaces every comment byte except newlines with a space, so
// the result has the same length and line structure as data. A JSON syntax
// error located in the result therefore names a line and column in the text
// the operator is looking at.
func BlankComments(data []byte) ([]byte, error) {
	spans, err := commentSpans(data)
	if err != nil {
		return nil, err
	}
	if len(spans) == 0 {
		return data, nil
	}
	return blankSpans(data, spans), nil
}

// commentSpan is one comment's [start, end) byte range in the source.
type commentSpan struct{ start, end int }

// commentSpans finds every comment outside a JSON string. A "/" that starts
// neither comment form is left for the JSON decoder to reject.
func commentSpans(data []byte) ([]commentSpan, error) {
	var spans []commentSpan
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			switch c {
			case '\\':
				i++ // the escaped byte cannot end the string
			case '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			end := bytes.IndexByte(data[i:], '\n')
			if end < 0 {
				end = len(data)
			} else {
				end += i
			}
			spans = append(spans, commentSpan{i, end})
			i = end - 1
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return nil, errUnterminatedComment
			}
			end += i + 2 + len("*/")
			spans = append(spans, commentSpan{i, end})
			i = end - 1
		}
	}
	return spans, nil
}

// deleteSpans replaces every comment with its newlines, or with one space
// when it has none, so the tokens on either side never join.
func deleteSpans(data []byte, spans []commentSpan) []byte {
	out := make([]byte, 0, len(data))
	pos := 0
	for _, span := range spans {
		out = append(out, data[pos:span.start]...)
		newlines := 0
		for _, c := range data[span.start:span.end] {
			if c == '\n' {
				out = append(out, c)
				newlines++
			}
		}
		if newlines == 0 {
			out = append(out, ' ')
		}
		pos = span.end
	}
	return append(out, data[pos:]...)
}

func blankSpans(data []byte, spans []commentSpan) []byte {
	out := bytes.Clone(data)
	for _, span := range spans {
		for i := span.start; i < span.end; i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return out
}

// touchedLines reports, by line index, the lines a comment occupies.
func touchedLines(data []byte, spans []commentSpan) map[int]bool {
	touched := map[int]bool{}
	line, pos := 0, 0
	for _, span := range spans {
		for ; pos < span.start; pos++ {
			if data[pos] == '\n' {
				line++
			}
		}
		touched[line] = true
		for ; pos < span.end; pos++ {
			if data[pos] == '\n' {
				line++
				if pos+1 < span.end {
					touched[line] = true
				}
			}
		}
	}
	return touched
}
