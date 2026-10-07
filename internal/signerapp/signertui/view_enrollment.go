// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Client enrollment popup view rendering.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderClientEnrollmentPopup renders the client enrollment approval popup
func (m Model) renderClientEnrollmentPopup() string {
	if m.enrollmentApproval.request == nil {
		return m.renderKeyListView()
	}

	req := m.enrollmentApproval.request
	rows := []string{
		"Client Enrollment Request",
		fmt.Sprintf("Client SSH key fingerprint: %s", req.SSHFingerprint),
		fmt.Sprintf("Remote Addr: %s", req.RemoteAddr),
	}
	if req.Label != "" {
		rows = append(rows, fmt.Sprintf("Requested label: %s", req.Label))
	}
	var sb strings.Builder

	sb.WriteString(titleStyle.Render(rows[0]))
	sb.WriteString("\n\n")
	for _, row := range rows[1:] {
		sb.WriteString(row + "\n")
	}
	sb.WriteString(subtitleStyle.Render("Approving enrolls this key as a client. No credential is issued."))
	sb.WriteString("\n\n")

	// Buttons - use JoinHorizontal for proper alignment
	var approveBtn, rejectBtn string
	if m.enrollmentApproval.focus == 0 {
		approveBtn = buttonActiveStyle.Render("> APPROVE")
		rejectBtn = buttonInactiveStyle.Render("  REJECT")
	} else {
		approveBtn = buttonInactiveStyle.Render("  APPROVE")
		rejectBtn = buttonActiveStyle.Render("> REJECT")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Center, approveBtn, "  ", rejectBtn)
	rows = append(rows, buttons)
	sb.WriteString(buttons)

	return m.renderPopup(enrollmentPopupWidth(rows), sb.String())
}

func enrollmentPopupWidth(rows []string) int {
	width := 0
	for _, row := range rows {
		if w := lipgloss.Width(row); w > width {
			width = w
		}
	}
	return width
}
