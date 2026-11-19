// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package secretbuf grows and shrinks byte buffers that hold a secret being
// typed, such as a passphrase in a terminal form, so they can be zeroed.
//
// A plain append that outgrows its capacity abandons the old backing array
// with the prefix typed so far still in it, and a plain reslice leaves the
// removed bytes behind. These functions own both: growth moves the bytes to a
// new allocation and zeroes the whole old one, and trimming zeroes what it
// removes.
package secretbuf

import "unicode/utf8"

// Grow returns buf with room for n more bytes. When buf must grow, its bytes
// move to a new allocation and the whole old one is zeroed.
func Grow[S ~[]byte](buf S, n int) S {
	if len(buf)+n <= cap(buf) {
		return buf
	}
	grown := make(S, len(buf), max(2*cap(buf), len(buf)+n))
	copy(grown, buf)
	clear(buf[:cap(buf)])
	return grown
}

// AppendRune appends r, UTF-8 encoded, to buf. An invalid rune is written as
// U+FFFD.
func AppendRune[S ~[]byte](buf S, r rune) S {
	if utf8.RuneLen(r) < 0 {
		r = utf8.RuneError
	}
	return utf8.AppendRune(Grow(buf, utf8.RuneLen(r)), r)
}

// AppendText appends the bytes of s, such as one typed key, to buf.
func AppendText[S ~[]byte](buf S, s string) S {
	return append(Grow(buf, len(s)), s...)
}

// TrimRune removes the last rune of buf and zeroes its bytes.
func TrimRune[S ~[]byte](buf S) S {
	if len(buf) == 0 {
		return buf
	}
	_, n := utf8.DecodeLastRune(buf)
	end := len(buf) - n
	clear(buf[end:])
	return buf[:end]
}
