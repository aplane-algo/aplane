// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package secretbuf

import (
	"bytes"
	"testing"
)

type named []byte

func allZero(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}

func TestGrowZeroesOutgrownBuffer(t *testing.T) {
	buf := AppendText(make([]byte, 0, 4), "abcd")
	old := buf[:cap(buf)]
	buf = AppendText(buf, "e")
	if string(buf) != "abcde" || !allZero(old) {
		t.Fatalf("grew to %q and left %q behind", buf, old)
	}
	if same := Grow(buf, 1); &same[:cap(same)][0] != &buf[:cap(buf)][0] {
		t.Fatal("Grow reallocated a buffer that had room")
	}
}

func TestAppendRuneKeepsNamedTypeAndReplacesInvalidRunes(t *testing.T) {
	buf := AppendRune(named("a"), 'ä')
	buf = AppendRune(buf, rune(-1))
	if string(buf) != "aä�" {
		t.Fatalf("AppendRune = %q", buf)
	}
}

func TestTrimRuneZeroesRemovedRune(t *testing.T) {
	buf := []byte("abä")
	full := buf[:cap(buf)]
	buf = TrimRune(buf)
	if string(buf) != "ab" || !allZero(full[2:]) {
		t.Fatalf("trimmed to %q, buffer %q", buf, full)
	}
	if got := TrimRune([]byte(nil)); len(got) != 0 {
		t.Fatalf("TrimRune(nil) = %q", got)
	}
}
