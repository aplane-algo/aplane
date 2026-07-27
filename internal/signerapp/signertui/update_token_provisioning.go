// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// handleTokenProvisioningPopupKeys handles keyboard input on token provisioning popup
func (m Model) handleTokenProvisioningPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	requestID := ""
	if m.tokenApproval.request != nil {
		requestID = m.tokenApproval.request.ID
	}

	m, cmd, focus, _ := m.handleApprovalKeys(msg, m.tokenApproval.focus, requestID,
		func(m Model, id string, approved bool) (Model, tea.Cmd) {
			m.tokenApproval.request = nil
			if m.signerState == signerRuntimeRecovery {
				// Recovery is blocking: resolving an enrollment popup must
				// return to the blocking recovery screen, never to normal
				// navigation.
				m.viewState = ViewRecoveredList
				return m, tea.Batch(m.sendTokenProvisioningResponse(id, approved), m.sendListRecoveredCmd())
			}
			m.viewState = ViewKeyList
			return m, m.sendTokenProvisioningResponse(id, approved)
		})
	m.tokenApproval.focus = focus
	return m, cmd
}

// sendTokenProvisioningResponse sends a token provisioning response via IPC
func (m Model) sendTokenProvisioningResponse(requestID string, approved bool) tea.Cmd {
	return m.sendTokenProvisioningResponseCmd(requestID, approved)
}
