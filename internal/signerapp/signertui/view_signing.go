// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Signing popup view rendering.

import (
	"strings"
)

// renderSigningPopup renders the signing approval popup
func (m Model) renderSigningPopup() string {
	if m.signing.request == nil {
		return m.renderKeyListView()
	}
	if m.reviewAvailable() {
		return m.renderReviewScreen(m.signing.request.Review)
	}
	return m.renderUnreviewableSigningRequest()
}

// renderUnreviewableSigningRequest is the signing popup for a request that
// came without its review. The signer sends every request with one, so a
// request without one can only be rejected.
func (m Model) renderUnreviewableSigningRequest() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Signing Request"))
	sb.WriteString("\n\n")
	// The decoder already made the request's text terminal-safe.
	sb.WriteString("Address: " + m.signing.request.Address + "\n\n")
	sb.WriteString(warningStyle.Render(wrapPlainText(unreviewableSigningRequestText, m.popupBodyWidth(60))))
	sb.WriteString("\n\n")
	sb.WriteString(buttonActiveStyle.BorderForeground(buttonDanger).Foreground(buttonDanger).Render("> REJECT"))
	return m.renderPopup(60, sb.String())
}

const unreviewableSigningRequestText = "This request came without a transaction review, so it cannot be approved here."
