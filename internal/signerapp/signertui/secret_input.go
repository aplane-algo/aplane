// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "unicode/utf8"

// Passphrase fields are byte buffers rather than strings so they can be
// zeroed. These helpers own their growth and shrinking: a plain append that
// outgrows its capacity abandons the old backing array with the prefix typed
// so far still in it, and a plain reslice leaves the removed bytes behind.

// growSecret returns buf with room for n more bytes. When buf must grow, its
// bytes move to a new allocation and the whole old one is zeroed.
func growSecret[S ~[]byte](buf S, n int) S {
	if len(buf)+n <= cap(buf) {
		return buf
	}
	grown := make(S, len(buf), max(2*cap(buf), len(buf)+n))
	copy(grown, buf)
	clear(buf[:cap(buf)])
	return grown
}

// appendSecretRune appends r, UTF-8 encoded, to buf. An invalid rune is
// written as U+FFFD.
func appendSecretRune[S ~[]byte](buf S, r rune) S {
	if utf8.RuneLen(r) < 0 {
		r = utf8.RuneError
	}
	return utf8.AppendRune(growSecret(buf, utf8.RuneLen(r)), r)
}

// appendSecretText appends the bytes of s, a typed key, to buf.
func appendSecretText[S ~[]byte](buf S, s string) S {
	return append(growSecret(buf, len(s)), s...)
}

// trimSecretRune removes the last rune of buf and zeroes its bytes.
func trimSecretRune[S ~[]byte](buf S) S {
	if len(buf) == 0 {
		return buf
	}
	_, n := utf8.DecodeLastRune(buf)
	end := len(buf) - n
	clear(buf[end:])
	return buf[:end]
}
