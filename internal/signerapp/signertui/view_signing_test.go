// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
)

func TestWrapTextContinuationIndentDoesNotExceedWidth(t *testing.T) {
	wrapped := wrapText("    "+strings.Repeat("abcde", 8), 8)
	for _, line := range strings.Split(wrapped, "\n") {
		if width := visibleWidth(line); width > 8 {
			t.Fatalf("wrapped line width = %d, want <= 8\nline: %q\nwrapped:\n%s",
				width, stripANSI(line), stripANSI(wrapped))
		}
	}
}
