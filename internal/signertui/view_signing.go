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
	if m.pendingSign == nil {
		return m.renderKeyListView()
	}

	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Signing Request"))
	sb.WriteString("\n\n")

	if isGroupApprovalDescription(m.pendingSign.Description) {
		sb.WriteString(fmt.Sprintf("Group:   %s\n", m.pendingSign.TxnSender))
		if m.pendingSign.Address != "" {
			sb.WriteString(fmt.Sprintf("Auth:    %s\n", m.pendingSign.Address))
		}
	} else {
		sb.WriteString(fmt.Sprintf("Address: %s\n", m.pendingSign.Address))
		if m.pendingSign.TxnSender != "" && m.pendingSign.TxnSender != m.pendingSign.Address {
			sb.WriteString(fmt.Sprintf("Sender:  %s (rekeyed)\n", m.pendingSign.TxnSender))
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
	sb.WriteString(viewportStyle.Render(m.pendingSignViewport.View()))

	// Show scroll indicator
	scrollPct := m.pendingSignViewport.ScrollPercent() * 100
	if m.pendingSignViewport.TotalLineCount() > m.pendingSignViewport.Height {
		sb.WriteString(fmt.Sprintf("\n[%.0f%% - %d lines]", scrollPct, m.pendingSignViewport.TotalLineCount()))
	}
	sb.WriteString("\n\n")

	// Validity window (if available)
	if m.pendingSign.FirstValid > 0 && m.pendingSign.LastValid > 0 {
		window := m.pendingSign.LastValid - m.pendingSign.FirstValid
		sb.WriteString(fmt.Sprintf("Valid Rounds: %d - %d (window: %d blocks)\n\n",
			m.pendingSign.FirstValid, m.pendingSign.LastValid, window))
	}

	// Display policy violations prominently (outside viewport so they're always visible)
	if len(m.pendingSign.Violations) > 0 {
		sb.WriteString(warningStyle.Render(fmt.Sprintf("⚠ %d WARNING(S) - scroll down in details to review", len(m.pendingSign.Violations))))
		sb.WriteString("\n\n")
	}

	// Buttons - use JoinHorizontal for proper alignment
	var approveBtn, rejectBtn string
	if m.pendingSignFocus == 0 {
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
