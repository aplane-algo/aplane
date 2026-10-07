// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// queueEnrollmentRequest shows an announced enrollment request, or queues it
// behind the one already on screen. A request announced twice (at login,
// after it was already shown) is not shown twice.
func (m *Model) queueEnrollmentRequest(req PendingEnrollmentRequest) {
	if m.enrollmentApproval.request != nil {
		if m.enrollmentApproval.request.ID == req.ID {
			return
		}
		for _, queued := range m.enrollmentApproval.queue {
			if queued.ID == req.ID {
				return
			}
		}
		m.enrollmentApproval.queue = append(m.enrollmentApproval.queue, req)
		return
	}
	m.enrollmentApproval.request = &req
	m.enrollmentApproval.focus = 1 // Default to reject button (safety-first)
}

// nextEnrollmentRequest moves the next queued request onto the popup, if any.
func (m *Model) nextEnrollmentRequest() bool {
	if len(m.enrollmentApproval.queue) == 0 {
		m.enrollmentApproval.request = nil
		return false
	}
	next := m.enrollmentApproval.queue[0]
	m.enrollmentApproval.queue = m.enrollmentApproval.queue[1:]
	m.enrollmentApproval.request = &next
	m.enrollmentApproval.focus = 1
	return true
}

// handleClientEnrollmentPopupKeys handles keyboard input on the enrollment
// request popup. The answer names the key; the request waits in the signer's
// queue until then, so there is nothing to time out.
func (m Model) handleClientEnrollmentPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	requestID := ""
	fingerprint := ""
	if m.enrollmentApproval.request != nil {
		requestID = m.enrollmentApproval.request.ID
		fingerprint = m.enrollmentApproval.request.SSHFingerprint
	}

	m, cmd, focus, _ := m.handleApprovalKeys(msg, m.enrollmentApproval.focus, requestID,
		func(m Model, _ string, approved bool) (Model, tea.Cmd) {
			answer := m.sendRejectEnrollmentCmd(fingerprint)
			if approved {
				answer = m.sendApproveEnrollmentCmd(fingerprint, "")
			}
			if m.nextEnrollmentRequest() {
				// Another request is waiting; keep the popup up for it.
				return m, tea.Batch(answer, m.waitForMessageCmd())
			}
			if m.signerState == signerRuntimeRecovery {
				// Recovery is blocking: resolving an enrollment popup must
				// return to the blocking recovery screen, never to normal
				// navigation.
				m.viewState = ViewStoreRecovery
				return m, tea.Batch(answer, m.waitForMessageCmd())
			}
			m.viewState = m.screenUnderApproval()
			return m, answer
		})
	m.enrollmentApproval.focus = focus
	return m, cmd
}
