// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

// Signing popup view rendering.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderSigningPopup renders the signing approval popup
func (m Model) renderSigningPopup() string {
	if m.pendingSign == nil {
		return m.renderKeyListView()
	}

	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Signing Request"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.pendingSign.Address))
	if m.pendingSign.TxnSender != "" && m.pendingSign.TxnSender != m.pendingSign.Address {
		sb.WriteString(fmt.Sprintf("Sender:  %s (rekeyed)\n", m.pendingSign.TxnSender))
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

	// Display policy violations prominently
	if len(m.pendingSign.Violations) > 0 {
		for _, v := range m.pendingSign.Violations {
			if v.Severity == "critical" {
				sb.WriteString(criticalStyle.Render("⚠ CRITICAL: " + v.Field))
				sb.WriteString("\n")
				sb.WriteString(errorStyle.Render("   " + v.Message))
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("   Value: %s\n\n", v.Value))
			} else {
				sb.WriteString(warningStyle.Render("⚠ WARNING: " + v.Field))
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("   %s\n", v.Message))
				sb.WriteString(fmt.Sprintf("   Value: %s\n\n", v.Value))
			}
		}
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
	sb.WriteString("\n\n")

	sb.WriteString(helpStyle.Render("y/a: Approve | n/r: Reject | ↑↓/jk: Scroll | Tab/←→: Switch | Enter: Confirm"))

	popup := popupStyle.Width(100).Render(sb.String())

	// Center the popup (simple version)
	return "\n" + popup
}
