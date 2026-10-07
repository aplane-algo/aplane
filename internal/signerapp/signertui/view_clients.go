// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Enrolled-clients screen, its revocation dialog, and the key import form.

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// renderEnrolledClients lists the enrollment requests waiting for approval
// and the enrolled client keys.
func (m Model) renderEnrolledClients() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Enrolled Clients"))
	sb.WriteString("\n")
	if m.clients.loading && len(m.clients.keys) == 0 && len(m.clients.pending) == 0 {
		sb.WriteString(subtitleStyle.Render("Loading enrollment requests and enrolled client keys..."))
		return sb.String()
	}
	sb.WriteString(subtitleStyle.Render("Each key is one client's credential. Approving a request enrolls its key; revoking a key closes its connections."))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Waiting for approval (%d)\n", len(m.clients.pending)))
	if len(m.clients.pending) == 0 {
		sb.WriteString("  none. Clients request enrollment with: request-enrollment\n")
	}
	for i, req := range m.clients.pending {
		cursor := "  "
		if i == m.clients.selected {
			cursor = "> "
		}
		line := cursor + req.Fingerprint
		if req.Label != "" {
			line += "  " + req.Label
		}
		line += "  " + req.KeyType
		if req.RemoteAddr != "" {
			line += "  from " + req.RemoteAddr
		}
		line += "  " + time.Unix(req.RequestedAt, 0).Local().Format("2006-01-02 15:04")
		sb.WriteString(line + "\n")
	}

	sb.WriteString(fmt.Sprintf("\nEnrolled (%d)\n", len(m.clients.keys)))
	if len(m.clients.keys) == 0 {
		sb.WriteString("  no enrolled client keys\n")
	}
	for i, key := range m.clients.keys {
		cursor := "  "
		if i+len(m.clients.pending) == m.clients.selected {
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

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("a approve  x reject  r revoke  A revoke all  i import key file  R refresh  esc back"))
	sb.WriteString("\n")
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
	sb.WriteString(subtitleStyle.Render("A revoked client must request enrollment again with: request-enrollment"))
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

// renderImportClientKey renders the pre-enrollment form: a public-key file
// on this machine and an optional label.
func (m Model) renderImportClientKey() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Import Client Key"))
	body.WriteString("\n\n")
	body.WriteString(subtitleStyle.Render("Enroll a client's SSH public key without a request from it. Verify the key's fingerprint with the client's owner first."))
	body.WriteString("\n\nPublic key file (one OpenSSH public-key line, e.g. id_ed25519.pub):\n")
	pathStyle := inputInactiveStyle
	if m.clients.importFocus == importClientKeyFocusPath {
		pathStyle = inputActiveStyle
	}
	body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(m.clients.importPath))
	body.WriteString("\n\nLabel (optional; the file's comment is used when empty):\n")
	labelStyle := inputInactiveStyle
	if m.clients.importFocus == importClientKeyFocusLabel {
		labelStyle = inputActiveStyle
	}
	body.WriteString(labelStyle.Width(m.constrainParameterFieldWidth(60)).Render(m.clients.importLabel))
	body.WriteString("\n\n")
	button := buttonInactiveStyle.Render("ENROLL KEY")
	if m.clients.importFocus == importClientKeyFocusButton {
		button = buttonActiveStyle.Render("ENROLL KEY")
	}
	body.WriteString(button)
	body.WriteString("\n")
	if m.clients.importError != "" {
		body.WriteString("\n" + errorStyle.Render(m.clients.importError) + "\n")
	}
	body.WriteString("\n" + helpStyle.Render("tab next field  enter submit  esc cancel"))
	return m.renderPopup(90, body.String())
}
