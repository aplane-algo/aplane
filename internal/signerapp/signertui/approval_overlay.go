// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Approval popups sit on top of every other screen. A signing or enrollment
// request stays on screen until the operator answers it or apsigner withdraws
// it. Background results that arrive meanwhile update the screen underneath,
// and answering returns to that screen.

// approvalOverlay remembers the screen under an approval popup.
type approvalOverlay struct {
	returnView ViewState
	hasReturn  bool
}

func isApprovalView(view ViewState) bool {
	return view == ViewSigningPopup || view == ViewClientEnrollmentPopup
}

// approvalPending reports whether view is an approval popup whose request is
// still waiting for the operator.
func (m Model) approvalPending(view ViewState) bool {
	switch view {
	case ViewSigningPopup:
		return m.signing.request != nil
	case ViewClientEnrollmentPopup:
		return m.enrollmentApproval.request != nil
	}
	return false
}

// screenUnderApproval returns the screen an answered approval returns to.
func (m Model) screenUnderApproval() ViewState {
	if m.approval.hasReturn {
		return m.approval.returnView
	}
	return ViewKeyList
}

// keepApprovalOnTop shows a pending approval over whatever screen the last
// update selected, recording that screen as the one to return to. preferred is
// the popup that was showing, which stays in front while it is pending.
func (m Model) keepApprovalOnTop(preferred ViewState) Model {
	popup := preferred
	if !m.approvalPending(popup) {
		switch {
		case m.signing.request != nil:
			popup = ViewSigningPopup
		case m.enrollmentApproval.request != nil:
			popup = ViewClientEnrollmentPopup
		default:
			if isApprovalView(m.viewState) {
				m.viewState = m.screenUnderApproval()
			}
			m.approval = approvalOverlay{}
			return m
		}
	}
	if !isApprovalView(m.viewState) {
		m.approval = approvalOverlay{returnView: m.viewState, hasReturn: true}
	}
	m.viewState = popup
	return m
}

// clearPendingApprovals drops approval requests that apsigner has already
// failed: it rejects every pending approval when the admin session ends or the
// signer locks, without a per-request cancel.
func (m *Model) clearPendingApprovals() {
	m.signing.request = nil
	m.enrollmentApproval.request = nil
	m.enrollmentApproval.queue = nil
}
