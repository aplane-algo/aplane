// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// queueEnrollmentRequest shows an announced enrollment request, or queues it
// behind the one already on screen. A request announced twice (at login,
// after it was already shown) is not shown twice, and neither is one the
// operator has already answered from the popup or the Enrolled Clients list.
func (m *Model) queueEnrollmentRequest(req PendingEnrollmentRequest) {
	if m.enrollmentAnswerInFlight(req.SSHFingerprint) {
		return
	}
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

// markEnrollmentAnswered records that an answer for fingerprint is in flight
// and drops any other announcement of the same request from the popup queue.
func (m *Model) markEnrollmentAnswered(fingerprint string) {
	if !m.enrollmentAnswerInFlight(fingerprint) {
		m.enrollmentApproval.answering = append(append([]string(nil), m.enrollmentApproval.answering...), fingerprint)
	}
	queue := make([]PendingEnrollmentRequest, 0, len(m.enrollmentApproval.queue))
	for _, queued := range m.enrollmentApproval.queue {
		if queued.SSHFingerprint != fingerprint {
			queue = append(queue, queued)
		}
	}
	m.enrollmentApproval.queue = queue
}

// settleEnrollmentAnswer forgets an in-flight answer once the signer has
// replied to it.
func (m *Model) settleEnrollmentAnswer(fingerprint string) {
	answering := make([]string, 0, len(m.enrollmentApproval.answering))
	for _, fp := range m.enrollmentApproval.answering {
		if fp != fingerprint {
			answering = append(answering, fp)
		}
	}
	m.enrollmentApproval.answering = answering
}

func (m Model) enrollmentAnswerInFlight(fingerprint string) bool {
	for _, fp := range m.enrollmentApproval.answering {
		if fp == fingerprint {
			return true
		}
	}
	return false
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
// queue until then, so there is nothing to time out. Esc defers the request:
// nothing is sent, the request stays in the signer's queue and on the
// Enrolled Clients screen, and the popup moves on to the next waiting request
// (or closes).
func (m Model) handleClientEnrollmentPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		return m.leaveEnrollmentPopup(nil)
	}

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
			m.markEnrollmentAnswered(fingerprint)
			return m.leaveEnrollmentPopup(answer)
		})
	m.enrollmentApproval.focus = focus
	return m, cmd
}

// leaveEnrollmentPopup moves the popup on from the request it showed, after
// an answer (sent by cmd) or a deferral (cmd is nil): the next waiting
// request takes the popup, or the popup closes onto the screen beneath it.
func (m Model) leaveEnrollmentPopup(cmd tea.Cmd) (Model, tea.Cmd) {
	if m.nextEnrollmentRequest() {
		// Another request is waiting; keep the popup up for it.
		return m, tea.Batch(cmd, m.waitForMessageCmd())
	}
	if m.signerState == signerRuntimeRecovery {
		// Recovery is blocking: leaving an enrollment popup must return to
		// the blocking recovery screen, never to normal navigation.
		m.viewState = ViewStoreRecovery
		return m, tea.Batch(cmd, m.waitForMessageCmd())
	}
	m.viewState = m.screenUnderApproval()
	return m, cmd
}
