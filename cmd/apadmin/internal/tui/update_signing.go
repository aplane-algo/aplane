// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

import (
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

// handleSigningPopupKeys handles keyboard input on signing popup
func (m Model) handleSigningPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left":
		m.pendingSignFocus = 0 // Approve

	case "right":
		m.pendingSignFocus = 1 // Reject

	case "tab":
		m.pendingSignFocus = (m.pendingSignFocus + 1) % 2

	case "enter", " ":
		approved := m.pendingSignFocus == 0
		requestID := ""
		if m.pendingSign != nil {
			requestID = m.pendingSign.ID
		}
		m.pendingSign = nil
		m.viewState = ViewKeyList
		return m, sendSignResponse(requestID, approved)

	case "y", "a":
		// Quick approve
		requestID := ""
		if m.pendingSign != nil {
			requestID = m.pendingSign.ID
		}
		m.pendingSign = nil
		m.viewState = ViewKeyList
		return m, sendSignResponse(requestID, true)

	case "n", "r", "esc":
		// Quick reject
		requestID := ""
		if m.pendingSign != nil {
			requestID = m.pendingSign.ID
		}
		m.pendingSign = nil
		m.viewState = ViewKeyList
		return m, sendSignResponse(requestID, false)

	case "up", "k":
		// Scroll up
		m.pendingSignViewport.ScrollUp(1)

	case "down", "j":
		// Scroll down
		m.pendingSignViewport.ScrollDown(1)

	case "pgup":
		// Page up
		m.pendingSignViewport.PageUp()

	case "pgdown":
		// Page down
		m.pendingSignViewport.PageDown()
	}

	return m, nil
}

// initSigningViewport initializes the viewport for the signing popup description
func (m *Model) initSigningViewport(content string) {
	// Viewport height - cap at 12 lines for compact display
	vpHeight := 12
	if m.height-16 < vpHeight {
		vpHeight = m.height - 16
	}
	if vpHeight < 5 {
		vpHeight = 5
	}

	// Viewport width - must fit inside popup (100) with padding
	vpWidth := 90
	if m.width-10 < vpWidth {
		vpWidth = m.width - 10
	}
	if vpWidth < 60 {
		vpWidth = 60
	}

	m.pendingSignViewport = viewport.New(vpWidth, vpHeight)
	m.pendingSignViewport.SetContent(content)
}

// sendUnlockRequest sends an unlock request via WebSocket
func sendUnlockRequest(passphrase string) tea.Cmd {
	return SendUnlockCmd(passphrase)
}

// sendSignResponse sends a sign response via WebSocket
func sendSignResponse(requestID string, approved bool) tea.Cmd {
	return sendSignResponseCmd(requestID, approved)
}
