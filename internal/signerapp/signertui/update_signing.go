// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/protocol"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

const signingDetailsBoxHorizontalChrome = 4 // rounded border plus horizontal padding

// handleSigningPopupKeys handles keyboard input on signing popup
func (m Model) handleSigningPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	requestID := ""
	if m.signing.request != nil {
		requestID = m.signing.request.ID
	}

	m, cmd, focus, handled := m.handleApprovalKeys(msg, m.signing.focus, requestID,
		func(m Model, id string, approved bool) (Model, tea.Cmd) {
			m.signing.request = nil
			m.viewState = ViewKeyList
			return m, m.sendSignResponse(id, approved)
		})
	m.signing.focus = focus
	if handled {
		return m, cmd
	}

	// Signing-specific: viewport scrolling
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

// signingViewportDimensions returns (height, width) for the signing popup viewport.
func (m Model) signingViewportDimensions() (int, int) {
	// Fixed chrome around viewport:
	//   2  popup border (top + bottom)
	//   2  popup padding (top + bottom)
	//   3  title (bold + MarginBottom 1) + address
	//   1  blank before details label
	//   1  "Transaction Details" label
	//   2  viewport border (top + bottom)
	//   1  scroll indicator
	//   2  validity window + blank
	//   3  warning banner + blanks (when violations present)
	//   5  buttons (3 tall with RoundedBorder) + 2 blanks
	//   1  help text
	//   2  status bar + newline
	// = 25 lines of chrome
	vpHeight := m.height - 25
	if vpHeight < 3 {
		vpHeight = 3
	}

	vpWidth := m.popupBodyWidth(60) - signingDetailsBoxHorizontalChrome
	if vpWidth < 1 {
		vpWidth = 1
	}

	return vpHeight, vpWidth
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
			if v.Severity == "critical" {
				sb.WriteString(fmt.Sprintf("⚠ CRITICAL: %s\n", v.Field))
			} else {
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

// initSigningViewport initializes the viewport for the signing popup description
func (m *Model) initSigningViewport(content string) {
	vpHeight, vpWidth := m.signingViewportDimensions()
	m.signing.viewport = viewport.New(vpWidth, vpHeight)
	m.signing.viewport.SetContent(wrapText(content, vpWidth))
}

// resizeSigningViewport updates the viewport dimensions and reflows content after a terminal resize.
func (m *Model) resizeSigningViewport() {
	vpHeight, vpWidth := m.signingViewportDimensions()
	m.signing.viewport.Width = vpWidth
	m.signing.viewport.Height = vpHeight
	m.signing.viewport.SetContent(wrapText(m.buildSigningViewportContent(), vpWidth))
}

// wrapText wraps each line of text to fit within the given width.
// Preserves leading whitespace on continuation lines for readability.
func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}
	var result strings.Builder
	for _, line := range strings.Split(text, "\n") {
		// Work in runes: descriptions contain multi-byte characters (e.g. the
		// ⚠ violation marker) and byte indexing would split them mid-rune.
		runes := []rune(line)
		if len(runes) <= width {
			result.WriteString(line)
			result.WriteByte('\n')
			continue
		}
		// Detect leading whitespace to preserve indent on wrapped lines
		indentLen := 0
		for indentLen < len(runes) && runes[indentLen] == ' ' {
			indentLen++
		}
		wrapIndent := string(runes[:indentLen]) + "  "
		remaining := runes
		first := true
		for len(remaining) > 0 {
			prefix := ""
			w := width
			if !first {
				if len(wrapIndent) < width {
					prefix = wrapIndent
					w = width - len(prefix)
				}
			}
			if w < 1 {
				w = 1
			}
			if len(remaining) <= w {
				result.WriteString(prefix)
				result.WriteString(string(remaining))
				result.WriteByte('\n')
				break
			}
			// Find last space within width to break at word boundary
			breakAt := w
			for i := w; i > 0; i-- {
				if remaining[i] == ' ' {
					breakAt = i
					break
				}
			}
			result.WriteString(prefix)
			result.WriteString(string(remaining[:breakAt]))
			result.WriteByte('\n')
			remaining = remaining[breakAt:]
			for len(remaining) > 0 && remaining[0] == ' ' {
				remaining = remaining[1:]
			}
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

// sendUnlockRequest sends an unlock request via the admin protocol transport.
func (m Model) sendUnlockRequest(passphrase string) tea.Cmd {
	return m.sendUnlockCmd(passphrase)
}

// sendSignResponse sends a sign response via the admin protocol transport.
func (m Model) sendSignResponse(requestID string, approved bool) tea.Cmd {
	return m.sendSignResponseCmd(requestID, approved)
}
