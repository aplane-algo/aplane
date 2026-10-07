// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// handleClientEnrollmentPopupKeys handles keyboard input on token provisioning popup
func (m Model) handleClientEnrollmentPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	requestID := ""
	if m.enrollmentApproval.request != nil {
		requestID = m.enrollmentApproval.request.ID
	}

	m, cmd, focus, _ := m.handleApprovalKeys(msg, m.enrollmentApproval.focus, requestID,
		func(m Model, id string, approved bool) (Model, tea.Cmd) {
			m.enrollmentApproval.request = nil
			if m.signerState == signerRuntimeRecovery {
				// Recovery is blocking: resolving an enrollment popup must
				// return to the blocking recovery screen, never to normal
				// navigation.
				m.viewState = ViewStoreRecovery
				return m, tea.Batch(m.sendClientEnrollmentResponse(id, approved), m.waitForMessageCmd())
			}
			m.viewState = m.screenUnderApproval()
			return m, m.sendClientEnrollmentResponse(id, approved)
		})
	m.enrollmentApproval.focus = focus
	return m, cmd
}

// sendClientEnrollmentResponse sends a token provisioning response via IPC
func (m Model) sendClientEnrollmentResponse(requestID string, approved bool) tea.Cmd {
	return m.sendClientEnrollmentResponseCmd(requestID, approved)
}
