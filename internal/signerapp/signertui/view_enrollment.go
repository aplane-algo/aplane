// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Client enrollment popup view rendering.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/termsafe"
)

// renderClientEnrollmentPopup renders the client enrollment approval popup
func (m Model) renderClientEnrollmentPopup() string {
	if m.enrollmentApproval.request == nil {
		return m.renderKeyListView()
	}

	req := m.enrollmentApproval.request
	// Each field is one row the client's text cannot leave
	// (termsafe.Field): the fingerprint and the address keep names the client
	// cannot write, and the label is quoted in ASCII, so nothing the client
	// sent can draw a line that reads like a field.
	fields := func(width int) []string {
		rows := []string{
			termsafe.Field("Fingerprint: ", req.SSHFingerprint, width),
			termsafe.Field("Address: ", req.RemoteAddr, width),
		}
		if req.Label != "" {
			rows = append(rows, termsafe.QuotedField("Label: ", req.Label, width))
		}
		return rows
	}
	const title = "Client Enrollment Request"
	queued := len(m.enrollmentApproval.queue)
	note := "Approving enrolls this key as a client; the client then connects on its own. No credential is issued. Esc leaves the request waiting."
	if queued > 0 {
		note += fmt.Sprintf(" %d more request(s) waiting.", queued)
	}
	buttons := buttonPair(m.enrollmentApproval.focus, "APPROVE", "REJECT", nil)
	popupWidth := enrollmentPopupWidth(append(append([]string{title}, fields(0)...), buttons))
	width := m.popupBodyWidth(popupWidth)

	// The title's margin is the gap under it.
	var head strings.Builder
	head.WriteString(titleStyle.Render(title))
	head.WriteString("\n")
	for _, row := range fields(width) {
		head.WriteString(row + "\n")
	}

	// The request and the buttons stay whole; the note takes the rows they
	// leave, cut in the middle so it still ends with the requests waiting.
	noteLines := strings.Split(wrapPlainText(note, width), "\n")
	if available := m.popupContentHeight(); available > 0 {
		fixed := wrappedHeight(head.String()+"\n"+buttons, width)
		noteLines = wrapCutLines(note, width, max(available-fixed, 1))
	}
	return m.renderPopup(popupWidth, head.String()+subtitleStyle.Render(strings.Join(noteLines, "\n"))+"\n\n"+buttons)
}

// enrollmentPopupWidth is the popup width that holds the widest row inside
// the popup's padding, for a window whose size is not yet known.
func enrollmentPopupWidth(rows []string) int {
	width := 0
	for _, row := range rows {
		if w := lipgloss.Width(row); w > width {
			width = w
		}
	}
	return width + popupStyle.GetHorizontalPadding()
}
