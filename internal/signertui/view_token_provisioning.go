// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Token provisioning popup view rendering.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderTokenProvisioningPopup renders the token provisioning approval popup
func (m Model) renderTokenProvisioningPopup() string {
	if m.pendingTokenRequest == nil {
		return m.renderKeyListView()
	}

	rows := []string{
		"Client Enrollment Request",
		fmt.Sprintf("Identity:    %s", m.pendingTokenRequest.IdentityID),
		fmt.Sprintf("SSH Key:     %s", m.pendingTokenRequest.SSHFingerprint),
		fmt.Sprintf("Remote Addr: %s", m.pendingTokenRequest.RemoteAddr),
		fmt.Sprintf("Timestamp:   %s", m.pendingTokenRequest.Timestamp.Format("15:04:05")),
		"⚠ This will issue an API token and register this SSH key",
	}
	var sb strings.Builder

	sb.WriteString(titleStyle.Render(rows[0]))
	sb.WriteString("\n\n")

	sb.WriteString(rows[1] + "\n")
	sb.WriteString(rows[2] + "\n")
	sb.WriteString(rows[3] + "\n")
	sb.WriteString(rows[4] + "\n")
	sb.WriteString("\n")

	sb.WriteString(warningStyle.Render(rows[5]))
	sb.WriteString("\n\n")

	// Buttons - use JoinHorizontal for proper alignment
	var approveBtn, rejectBtn string
	if m.pendingTokenRequestFocus == 0 {
		approveBtn = buttonActiveStyle.Render("> APPROVE")
		rejectBtn = buttonInactiveStyle.Render("  REJECT")
	} else {
		approveBtn = buttonInactiveStyle.Render("  APPROVE")
		rejectBtn = buttonActiveStyle.Render("> REJECT")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Center, approveBtn, "  ", rejectBtn)
	rows = append(rows, buttons)
	sb.WriteString(buttons)

	popup := m.renderPopup(tokenProvisioningPopupWidth(rows), sb.String())

	// Center the popup (simple version)
	return "\n" + popup
}

func tokenProvisioningPopupWidth(rows []string) int {
	width := 0
	for _, row := range rows {
		if w := lipgloss.Width(row); w > width {
			width = w
		}
	}
	return width
}
