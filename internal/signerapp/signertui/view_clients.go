// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Enrolled-clients screen, its revocation dialog, and the key import form.

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

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
	sb.WriteString(subtitleStyle.Render(wrapPlainText("Each key is one client's credential. Approving a request enrolls its key; revoking a key closes its connections.", m.tableWidth())))
	sb.WriteString("\n\n")

	labelWidth := m.clientLabelWidth()
	sb.WriteString(fmt.Sprintf("Waiting for approval (%d)\n", len(m.clients.pending)))
	if len(m.clients.pending) == 0 {
		sb.WriteString("  none. Clients request enrollment with: enroll\n")
	}
	for i, req := range m.clients.pending {
		cursor := "  "
		if i == m.clients.selected {
			cursor = "> "
		}
		sb.WriteString(strings.TrimRight(clientRow(cursor, req.Fingerprint, req.Label, labelWidth), " ") + "\n")
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
		line := clientRow(cursor, key.Fingerprint, key.Label, labelWidth)
		if key.Connected {
			line += "  " + warningStyle.Render(clientConnectedFlag)
		}
		sb.WriteString(strings.TrimRight(line, " ") + "\n")
	}

	if details := m.selectedClientDetails(); len(details) > 0 {
		sb.WriteString("\n" + strings.Join(details, "\n") + "\n")
	}

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("a approve  x reject  r revoke  A revoke all  i import key file  esc back"))
	sb.WriteString("\n")
	if m.clients.status != "" {
		sb.WriteString("\n")
		sb.WriteString(m.clients.status)
		sb.WriteString("\n")
	}
	return sb.String()
}

// A fingerprint is compared by eye and approving acts on the selected row at
// once, so rows keep it whole. The label gets the rest of the row after the
// connected flag; selectedClientDetails shows it in full with everything else
// that does not fit on a row.
const (
	clientFingerprintWidth = 50 // "SHA256:" + 43 base64 characters
	clientConnectedFlag    = "connected"
	clientLabelMinWidth    = 8
)

func (m Model) clientLabelWidth() int {
	longest := 0
	for _, req := range m.clients.pending {
		longest = max(longest, utf8.RuneCountInString(terminalSafe(req.Label)))
	}
	for _, key := range m.clients.keys {
		longest = max(longest, utf8.RuneCountInString(terminalSafe(key.Label)))
	}
	const cursorAndGaps = 2 + 2 + 2
	room := m.tableWidth() - cursorAndGaps - clientFingerprintWidth - len(clientConnectedFlag)
	return min(longest, max(room, clientLabelMinWidth))
}

func clientRow(cursor, fingerprint, label string, labelWidth int) string {
	return fmt.Sprintf("%s%-*s  %-*s", cursor, clientFingerprintWidth, fingerprint,
		labelWidth, ellipsizeMiddle(terminalSafe(label), labelWidth))
}

// selectedClientDetails describes the selected row below the list.
func (m Model) selectedClientDetails() []string {
	field := func(label, value string) string { return fmt.Sprintf("%-11s%s", label+":", value) }
	var lines []string
	addLabel := func(label string) {
		if label != "" {
			lines = append(lines, field("Label", terminalSafe(label)))
		}
	}
	selected := m.clients.selected
	if selected >= 0 && selected < len(m.clients.pending) {
		req := m.clients.pending[selected]
		addLabel(req.Label)
		lines = append(lines, field("Key type", req.KeyType))
		if req.RemoteAddr != "" {
			lines = append(lines, field("From", req.RemoteAddr))
		}
		return append(lines, field("Requested", time.Unix(req.RequestedAt, 0).Local().Format("2006-01-02 15:04")))
	}
	if index := selected - len(m.clients.pending); index >= 0 && index < len(m.clients.keys) {
		key := m.clients.keys[index]
		addLabel(key.Label)
		lines = append(lines, field("Key type", key.KeyType))
	}
	return lines
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
	sb.WriteString(subtitleStyle.Render("A revoked client must request enrollment again with: enroll"))
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
	body.WriteString("\n")
	body.WriteString(subtitleStyle.Render(wrapPlainText("Enrolls a client's SSH public key directly; verify its fingerprint first.", m.popupBodyWidth(90))))
	body.WriteString("\n\nPublic key file (one OpenSSH public-key line, e.g. id_ed25519.pub):\n")
	pathStyle := inputInactiveStyle
	if m.clients.importFocus == importClientKeyFocusPath {
		pathStyle = inputActiveStyle
	}
	body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(terminalSafe(m.clients.importPath)))
	body.WriteString("\nLabel (optional; defaults to the file's comment):\n")
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
		body.WriteString("\n" + errorStyle.Render(terminalSafeLines(m.clients.importError)) + "\n")
	}
	return m.renderPopup(90, body.String())
}
