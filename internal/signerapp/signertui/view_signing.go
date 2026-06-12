// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Signing popup view rendering.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func isGroupApprovalDescription(desc string) bool {
	return strings.HasPrefix(desc, "[GROUP APPROVAL]\n")
}

// renderSigningPopup renders the signing approval popup
func (m Model) renderSigningPopup() string {
	if m.signing.request == nil {
		return m.renderKeyListView()
	}

	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Signing Request"))
	sb.WriteString("\n\n")

	if isGroupApprovalDescription(m.signing.request.Description) {
		sb.WriteString(fmt.Sprintf("Group:   %s\n", m.signing.request.TxnSender))
		if m.signing.request.Address != "" {
			sb.WriteString(fmt.Sprintf("Auth:    %s\n", m.signing.request.Address))
		}
	} else {
		sb.WriteString(fmt.Sprintf("Address: %s\n", m.signing.request.Address))
		if m.signing.request.TxnSender != "" && m.signing.request.TxnSender != m.signing.request.Address {
			sb.WriteString(fmt.Sprintf("Sender:  %s (auth claimed)\n", m.signing.request.TxnSender))
		}
	}
	sb.WriteString("\n")

	// Transaction description in scrollable viewport
	sb.WriteString("Transaction Details (↑/↓ to scroll):\n")

	// Render the viewport with a border style
	viewportStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240")).
		Padding(0, 1)
	sb.WriteString(viewportStyle.Render(m.signing.viewport.View()))

	// Show scroll indicator
	scrollPct := m.signing.viewport.ScrollPercent() * 100
	if m.signing.viewport.TotalLineCount() > m.signing.viewport.Height {
		sb.WriteString(fmt.Sprintf("\n[%.0f%% - %d lines]", scrollPct, m.signing.viewport.TotalLineCount()))
	}
	sb.WriteString("\n\n")

	// Validity window (if available)
	if m.signing.request.FirstValid > 0 && m.signing.request.LastValid > 0 {
		window := m.signing.request.LastValid - m.signing.request.FirstValid
		sb.WriteString(fmt.Sprintf("Valid Rounds: %d - %d (window: %d blocks)\n\n",
			m.signing.request.FirstValid, m.signing.request.LastValid, window))
	}

	// Display policy violations prominently (outside viewport so they're always visible)
	if len(m.signing.request.Violations) > 0 {
		sb.WriteString(warningStyle.Render(fmt.Sprintf("⚠ %d WARNING(S) - scroll down in details to review", len(m.signing.request.Violations))))
		sb.WriteString("\n\n")
	}

	// Buttons - use JoinHorizontal for proper alignment
	var approveBtn, rejectBtn string
	if m.signing.focus == 0 {
		approveBtn = buttonActiveStyle.Render("> APPROVE")
		rejectBtn = buttonInactiveStyle.Render("  REJECT")
	} else {
		approveBtn = buttonInactiveStyle.Render("  APPROVE")
		rejectBtn = buttonActiveStyle.Render("> REJECT")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Center, approveBtn, "  ", rejectBtn)
	sb.WriteString(buttons)

	return m.renderPopup(60, sb.String())
}
