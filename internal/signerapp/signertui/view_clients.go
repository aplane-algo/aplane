// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Enrolled-clients screen and its revocation dialog.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderEnrolledClients lists the enrolled client keys.
func (m Model) renderEnrolledClients() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Enrolled Clients"))
	sb.WriteString("\n")
	if m.clients.loading && len(m.clients.keys) == 0 {
		sb.WriteString(subtitleStyle.Render("Loading enrolled client keys..."))
		return sb.String()
	}
	sb.WriteString(subtitleStyle.Render("Each key is one client's credential. Revoking a key closes its connections; the client must re-enroll."))
	sb.WriteString("\n\n")
	if len(m.clients.keys) == 0 {
		sb.WriteString("No enrolled client keys. Clients enroll with: request-enrollment\n")
	}
	for i, key := range m.clients.keys {
		cursor := "  "
		if i == m.clients.selected {
			cursor = "> "
		}
		line := cursor + key.Fingerprint
		if key.Label != "" {
			line += "  " + key.Label
		}
		line += "  " + key.KeyType
		if key.Connected {
			line += "  " + warningStyle.Render("connected")
		}
		sb.WriteString(line + "\n")
	}
	if m.clients.status != "" {
		sb.WriteString("\n")
		sb.WriteString(m.clients.status)
		sb.WriteString("\n")
	}
	return sb.String()
}

// renderRevokeClientConfirm renders the client key revocation dialog.
func (m Model) renderRevokeClientConfirm() string {
	var sb strings.Builder
	if m.clients.confirmAll {
		sb.WriteString(errorStyle.Render("REVOKE ALL CLIENT KEYS"))
		sb.WriteString("\n\n")
		sb.WriteString(fmt.Sprintf("This removes all %d enrolled client key(s).\n\n", len(m.clients.keys)))
		sb.WriteString(errorStyle.Render("Every connected client will be disconnected."))
	} else {
		sb.WriteString(errorStyle.Render("REVOKE CLIENT KEY"))
		sb.WriteString("\n\n")
		sb.WriteString("Key: " + m.clients.confirmKey + "\n")
		if m.clients.confirmLabel != "" {
			sb.WriteString("Label: " + m.clients.confirmLabel + "\n")
		}
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render("This client's connections will be closed."))
	}
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("A revoked client must be enrolled again with: request-enrollment"))
	sb.WriteString("\n\n")

	var cancelBtn, revokeBtn string
	if m.clients.confirmFocus == 0 {
		cancelBtn = buttonActiveStyle.Render("> CANCEL")
		revokeBtn = buttonInactiveStyle.Render("  REVOKE")
	} else {
		cancelBtn = buttonInactiveStyle.Render("  CANCEL")
		revokeBtn = buttonActiveStyle.BorderForeground(lipgloss.Color("196")).Foreground(lipgloss.Color("196")).Render("> REVOKE")
	}
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Center, cancelBtn, "  ", revokeBtn))
	return m.renderPopup(80, sb.String())
}
