// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// handleTokenProvisioningPopupKeys handles keyboard input on token provisioning popup
func (m Model) handleTokenProvisioningPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	requestID := ""
	if m.pendingTokenRequest != nil {
		requestID = m.pendingTokenRequest.ID
	}

	m, cmd, focus, _ := m.handleApprovalKeys(msg, m.pendingTokenRequestFocus, requestID,
		func(m Model, id string, approved bool) (Model, tea.Cmd) {
			m.pendingTokenRequest = nil
			m.viewState = ViewKeyList
			return m, m.sendTokenProvisioningResponse(id, approved)
		})
	m.pendingTokenRequestFocus = focus
	return m, cmd
}

// sendTokenProvisioningResponse sends a token provisioning response via IPC
func (m Model) sendTokenProvisioningResponse(requestID string, approved bool) tea.Cmd {
	return m.sendTokenProvisioningResponseCmd(requestID, approved)
}
