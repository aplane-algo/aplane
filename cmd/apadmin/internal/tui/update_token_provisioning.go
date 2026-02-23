// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// handleTokenProvisioningPopupKeys handles keyboard input on token provisioning popup
func (m Model) handleTokenProvisioningPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left":
		m.pendingTokenRequestFocus = 0 // Approve

	case "right":
		m.pendingTokenRequestFocus = 1 // Reject

	case "tab":
		m.pendingTokenRequestFocus = (m.pendingTokenRequestFocus + 1) % 2

	case "enter", " ":
		approved := m.pendingTokenRequestFocus == 0
		requestID := ""
		if m.pendingTokenRequest != nil {
			requestID = m.pendingTokenRequest.ID
		}
		m.pendingTokenRequest = nil
		m.viewState = ViewKeyList
		return m, sendTokenProvisioningResponse(requestID, approved)

	case "y", "a":
		// Quick approve
		requestID := ""
		if m.pendingTokenRequest != nil {
			requestID = m.pendingTokenRequest.ID
		}
		m.pendingTokenRequest = nil
		m.viewState = ViewKeyList
		return m, sendTokenProvisioningResponse(requestID, true)

	case "n", "r", "esc":
		// Quick reject
		requestID := ""
		if m.pendingTokenRequest != nil {
			requestID = m.pendingTokenRequest.ID
		}
		m.pendingTokenRequest = nil
		m.viewState = ViewKeyList
		return m, sendTokenProvisioningResponse(requestID, false)
	}

	return m, nil
}

// sendTokenProvisioningResponse sends a token provisioning response via IPC
func sendTokenProvisioningResponse(requestID string, approved bool) tea.Cmd {
	return sendTokenProvisioningResponseCmd(requestID, approved)
}
