// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
)

func TestSigningPopupTransactionDetailsFitsPopupWidth(t *testing.T) {
	m := Model{
		width:  48,
		height: 32,
		signing: signingState{request: &PendingSignRequest{
			ID:          "sign-1",
			Address:     "ADDR",
			Description: "Payment\n    Note: " + strings.Repeat("abcdef", 20),
			FirstValid:  10,
			LastValid:   20,
		}},
	}
	m.initSigningViewport(m.buildSigningViewportContent())

	view := m.renderSigningPopup()
	for _, line := range strings.Split(view, "\n") {
		if width := visibleWidth(line); width > m.width {
			t.Fatalf("signing popup line width = %d, want <= %d\nline: %q\nview:\n%s",
				width, m.width, stripANSI(line), stripANSI(view))
		}
	}
}

func TestSigningViewportDimensionsLeaveRoomForDetailsBoxChrome(t *testing.T) {
	for _, width := range []int{32, 48, 80} {
		m := Model{width: width, height: 30}
		_, viewportWidth := m.signingViewportDimensions()
		if got, want := viewportWidth+signingDetailsBoxHorizontalChrome, m.popupBodyWidth(60); got > want {
			t.Fatalf("width %d: details box width = %d, want <= popup body width %d", width, got, want)
		}
		if got, want := viewportWidth+signingDetailsBoxHorizontalChrome, m.popupWidth(60); got >= want {
			t.Fatalf("width %d: details box width = %d, want < popup box width %d", width, got, want)
		}
	}
}

func TestWrapTextContinuationIndentDoesNotExceedWidth(t *testing.T) {
	wrapped := wrapText("    "+strings.Repeat("abcde", 8), 8)
	for _, line := range strings.Split(wrapped, "\n") {
		if width := visibleWidth(line); width > 8 {
			t.Fatalf("wrapped line width = %d, want <= 8\nline: %q\nwrapped:\n%s",
				width, stripANSI(line), stripANSI(wrapped))
		}
	}
}
