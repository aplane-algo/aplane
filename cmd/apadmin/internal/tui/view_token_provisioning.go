// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

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

	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Token Provisioning Request"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Identity:    %s\n", m.pendingTokenRequest.IdentityID))
	sb.WriteString(fmt.Sprintf("SSH Key:     %s\n", m.pendingTokenRequest.SSHFingerprint))
	sb.WriteString(fmt.Sprintf("Remote Addr: %s\n", m.pendingTokenRequest.RemoteAddr))
	sb.WriteString(fmt.Sprintf("Timestamp:   %s\n", m.pendingTokenRequest.Timestamp.Format("15:04:05")))
	sb.WriteString("\n")

	sb.WriteString(warningStyle.Render("⚠ This will grant API access to this SSH key"))
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
	sb.WriteString(buttons)
	sb.WriteString("\n\n")

	sb.WriteString(helpStyle.Render("y/a: Approve | n/r: Reject | Tab/←→: Switch | Enter: Confirm"))

	popup := popupStyle.Width(80).Render(sb.String())

	// Center the popup (simple version)
	return "\n" + popup
}
