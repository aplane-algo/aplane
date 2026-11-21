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
		fmt.Sprintf("Remote Addr: %s", terminalSafe(req.RemoteAddr)),
	}
	if req.Label != "" {
		// The label comes from the client, before the client is trusted.
		rows = append(rows, fmt.Sprintf("Requested label: %s", terminalSafe(req.Label)))
	}
	// The title's margin is the gap under it.
	var head strings.Builder
	head.WriteString(titleStyle.Render(rows[0]))
	head.WriteString("\n")
	for _, row := range rows[1:] {
		head.WriteString(row + "\n")
	}
	queued := len(m.enrollmentApproval.queue)
	note := "Approving enrolls this key as a client; the client then connects on its own. No credential is issued. Esc leaves the request waiting."
	if queued > 0 {
		note += fmt.Sprintf(" %d more request(s) waiting.", queued)
	}
	buttons := buttonPair(m.enrollmentApproval.focus, "APPROVE", "REJECT", nil)
	popupWidth := enrollmentPopupWidth(append(rows, buttons))
	width := m.popupBodyWidth(popupWidth)

	// The request and the buttons stay whole; the note takes the rows they
	// leave, cut in the middle so it still ends with the requests waiting.
	noteLines := strings.Split(wrapPlainText(note, width), "\n")
	if available := m.popupContentHeight(); available > 0 {
		fixed := wrappedHeight(head.String()+"\n"+buttons, width)
		noteLines = wrapCutLines(note, width, max(available-fixed, 1))
	}
	return m.renderPopup(popupWidth, head.String()+subtitleStyle.Render(strings.Join(noteLines, "\n"))+"\n\n"+buttons)
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
