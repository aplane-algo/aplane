// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/protocol"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// approvalArmDelay is how long a newly shown signing or enrollment request
// refuses approval.
const approvalArmDelay = time.Second

// signingNow is the clock for the arming delay of both popups; tests replace
// it.
var signingNow = time.Now

// handleSigningPopupKeys handles keyboard input on signing popup
func (m Model) handleSigningPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	requestID := ""
	if m.signing.request != nil {
		requestID = m.signing.request.ID
	}
	respond := func(m Model, id string, approved bool) (Model, tea.Cmd) {
		// A requester can withdraw a request and send another in its
		// place; a key pressed for the first must not approve the
		// second. Rejecting is always immediate.
		if approved && signingNow().Sub(m.signing.shownAt) < approvalArmDelay {
			return m, m.setTransientNotice("One moment...")
		}
		m.signing.request = nil
		m.viewState = m.screenUnderApproval()
		return m, m.sendSignResponseCmd(id, approved)
	}
	if !m.reviewAvailable() {
		// A request without its review has nothing to approve against:
		// the only answer is to reject it.
		switch msg.String() {
		case "enter", " ", "n", "r", "esc":
			return respond(m, requestID, false)
		}
		return m, nil
	}

	m, cmd, focus, handled := m.handleApprovalKeys(msg, m.signing.focus, requestID, respond)
	m.signing.focus = focus
	if handled {
		return m, cmd
	}
	if m, handled := m.handleReviewKeys(msg); handled {
		return m, nil
	}

	// The review's detail pane scrolls.
	switch msg.String() {
	case "up", "k":
		m.signing.viewport.ScrollUp(1)
	case "down", "j":
		m.signing.viewport.ScrollDown(1)
	case "pgup":
		m.signing.viewport.PageUp()
	case "pgdown":
		m.signing.viewport.PageDown()
	}

	return m, nil
}

func signRequestCanceledWarning(reason string) string {
	switch reason {
	case protocol.SignRequestCancelReasonClientCanceled:
		return "Signing request canceled by requester"
	case protocol.SignRequestCancelReasonTimeout:
		return "Signing request timed out"
	case protocol.SignRequestCancelReasonSessionEnded:
		return "Signing request withdrawn: the signer locked or its session ended"
	case protocol.SignRequestCancelReasonApproverDisplaced:
		return "Signing request withdrawn: another apadmin session took over"
	case protocol.SignRequestCancelReasonApproverDisconnected:
		return "Signing request withdrawn: its apadmin session disconnected"
	case "":
		return "Signing request canceled"
	default:
		return "Signing request canceled: " + reason
	}
}

// handleApprovalKeys handles the common approve/reject keyboard pattern.
// Returns (model, cmd, newFocus, handled). If handled is false, the caller should process the key.
func (m Model) handleApprovalKeys(
	msg tea.KeyMsg,
	focus int,
	requestID string,
	onRespond func(Model, string, bool) (Model, tea.Cmd),
) (Model, tea.Cmd, int, bool) {
	switch msg.String() {
	case "left":
		return m, nil, 0, true
	case "right":
		return m, nil, 1, true
	case "tab":
		return m, nil, (focus + 1) % 2, true
	case "enter", " ":
		m, cmd := onRespond(m, requestID, focus == 0)
		return m, cmd, focus, true
	case "y", "a":
		m, cmd := onRespond(m, requestID, true)
		return m, cmd, focus, true
	case "n", "r", "esc":
		m, cmd := onRespond(m, requestID, false)
		return m, cmd, focus, true
	}
	return m, nil, focus, false
}

// buildSigningViewportContent builds the scrollable content for the signing viewport,
// including the transaction description and any policy violations.
func (m Model) buildSigningViewportContent() string {
	if m.signing.request == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(m.signing.request.Description)

	if len(m.signing.request.Violations) > 0 {
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("=", 50))
		sb.WriteString("\n")
		for _, v := range m.signing.request.Violations {
			switch v.Severity {
			case protocol.ViolationSeverityCritical:
				sb.WriteString(fmt.Sprintf("⚠ CRITICAL: %s\n", v.Field))
			case protocol.ViolationSeverityNotice:
				sb.WriteString(fmt.Sprintf("Note: %s\n", v.Field))
			default:
				sb.WriteString(fmt.Sprintf("⚠ WARNING: %s\n", v.Field))
			}
			if v.Value != "" {
				sb.WriteString(fmt.Sprintf("   Value: %s\n", v.Value))
			}
			sb.WriteString(fmt.Sprintf("\n   %s\n\n", v.Message))
		}
	}

	return sb.String()
}

// initSigningViewport lays out a new request's review.
func (m *Model) initSigningViewport() {
	if m.reviewAvailable() {
		m.refreshReview()
	}
}

// resizeSigningViewport lays the review out again after a terminal resize.
// The detail pane keeps the operator's place, as far down as the new height
// allows.
func (m *Model) resizeSigningViewport() {
	if !m.reviewAvailable() {
		return
	}
	offset := m.signing.viewport.YOffset
	m.refreshReview()
	m.signing.viewport.SetYOffset(offset)
}

// wrapText wraps each line of text to fit within width columns, as the
// terminal draws them, at a space where it can. Preserves leading whitespace
// on continuation lines for readability.
func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}
	var result strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if ansi.StringWidth(line) <= width {
			result.WriteString(line)
			result.WriteByte('\n')
			continue
		}
		// Detect leading whitespace to preserve indent on wrapped lines
		wrapIndent := line[:len(line)-len(strings.TrimLeft(line, " "))] + "  "
		remaining := line
		first := true
		for remaining != "" {
			prefix := ""
			w := width
			if !first && len(wrapIndent) < width {
				prefix = wrapIndent
				w = width - len(prefix)
			}
			if ansi.StringWidth(remaining) <= w {
				result.WriteString(prefix + remaining + "\n")
				break
			}
			breakAt := wrapTextBreak(remaining, w)
			result.WriteString(prefix + remaining[:breakAt] + "\n")
			remaining = strings.TrimLeft(remaining[breakAt:], " ")
			first = false
		}
	}
	// Remove trailing newline added by the loop (original may not have one)
	s := result.String()
	if len(s) > 0 && s[len(s)-1] == '\n' && (len(text) == 0 || text[len(text)-1] != '\n') {
		s = s[:len(s)-1]
	}
	return s
}

// wrapTextBreak is where wrapText breaks s, wider than w columns: at the
// last space after its start that leaves at most w columns before it, else
// after the most that fit, and after at least one character.
func wrapTextBreak(s string, w int) int {
	fit := len(ansi.Truncate(s, w, ""))
	if fit < len(s) && s[fit] == ' ' {
		return fit
	}
	if space := strings.LastIndexByte(s[:fit], ' '); space > 0 {
		return space
	}
	if fit == 0 {
		_, fit = utf8.DecodeRuneInString(s)
	}
	return fit
}
