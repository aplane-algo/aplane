// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// armImmediately makes every approval popup armed by the time a key is
// checked: each reading of the clock is approvalArmDelay after the last.
func armImmediately(t *testing.T) {
	t.Helper()
	clock := time.Unix(1_000, 0)
	saved := signingNow
	signingNow = func() time.Time {
		clock = clock.Add(approvalArmDelay)
		return clock
	}
	t.Cleanup(func() { signingNow = saved })
}

// stoppedClock is a clock that moves only when the test moves it.
func stoppedClock(t *testing.T) *time.Time {
	t.Helper()
	clock := time.Unix(1_000, 0)
	saved := signingNow
	signingNow = func() time.Time { return clock }
	t.Cleanup(func() { signingNow = saved })
	return &clock
}

func enrollmentRequest(id string) ClientEnrollmentRequestReceivedMsg {
	return ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: id, SSHFingerprint: "SHA256:" + id}}
}

// An enrollment request that just appeared refuses approval, as a signing
// request does, so a key repeated from another screen cannot enroll a key
// nobody read. Rejection is never delayed.
func TestEnrollmentPopupRefusesApprovalUntilArmed(t *testing.T) {
	clock := stoppedClock(t)
	m := updateModel(t, approvalTestModel(ViewKeyList), enrollmentRequest("one"))
	*clock = clock.Add(200 * time.Millisecond)
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if m.enrollmentApproval.request == nil || m.viewState != ViewClientEnrollmentPopup || len(m.enrollmentApproval.answering) != 0 {
		t.Fatalf("approval within the arming delay was accepted: view %v answering %v", m.viewState, m.enrollmentApproval.answering)
	}
	if m.lastNotice != "One moment..." {
		t.Errorf("a refused approval says %q, want %q", m.lastNotice, "One moment...")
	}

	*clock = clock.Add(time.Second)
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if m.enrollmentApproval.request != nil || len(m.enrollmentApproval.answering) != 1 {
		t.Fatalf("approval after the arming delay was not accepted: request %+v", m.enrollmentApproval.request)
	}

	m = updateModel(t, m, enrollmentRequest("two"))
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.enrollmentApproval.request != nil {
		t.Fatal("rejection was delayed")
	}
}

// Answering one request with the focus on Approve leaves the next queued
// request on Reject, and armed only from when it appeared: a second Enter
// rejects it, and a second y is refused, so neither enrolls it unread.
func TestNextEnrollmentRequestOpensOnRejectAndUnarmed(t *testing.T) {
	clock := stoppedClock(t)
	m := approvalTestModel(ViewKeyList)
	m = updateModel(t, m, enrollmentRequest("one"))
	m = updateModel(t, m, enrollmentRequest("two"))
	m = updateModel(t, m, enrollmentRequest("three"))
	*clock = clock.Add(5 * time.Second)

	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyLeft}) // onto Approve
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.enrollmentApproval.request == nil || m.enrollmentApproval.request.ID != "two" {
		t.Fatalf("the popup did not move on to the second request: %+v", m.enrollmentApproval.request)
	}
	if m.enrollmentApproval.focus != 1 {
		t.Fatalf("the second request opened with focus %d, want 1 (Reject)", m.enrollmentApproval.focus)
	}

	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if m.enrollmentApproval.request == nil || m.enrollmentApproval.request.ID != "two" {
		t.Fatalf("y on the request that just appeared was accepted: %+v", m.enrollmentApproval.request)
	}
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.enrollmentApproval.request == nil || m.enrollmentApproval.request.ID != "three" {
		t.Fatalf("Enter did not answer the second request: %+v", m.enrollmentApproval.request)
	}
	if got := m.enrollmentApproval.answering; len(got) != 2 || got[1] != "SHA256:two" {
		t.Fatalf("answers in flight = %v", got)
	}
}

// An enrollment request that waited behind a signing prompt starts its
// arming delay when it comes into view, not when it arrived.
func TestEnrollmentPopupArmsWhenItBecomesVisible(t *testing.T) {
	clock := stoppedClock(t)
	m := approvalTestModel(ViewKeyList)
	m = updateModel(t, m, SignRequestReceivedMsg{Request: signRequest("sign-1")})
	m = updateModel(t, m, enrollmentRequest("one"))
	if m.viewState != ViewSigningPopup {
		t.Fatalf("view = %v, want the signing popup in front", m.viewState)
	}

	*clock = clock.Add(5 * time.Second)
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.viewState != ViewClientEnrollmentPopup {
		t.Fatalf("view after answering the signing prompt = %v, want the enrollment popup", m.viewState)
	}
	*clock = clock.Add(200 * time.Millisecond)
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if m.enrollmentApproval.request == nil {
		t.Fatal("the enrollment request accepted approval on its first moment in view")
	}
	*clock = clock.Add(time.Second)
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if m.enrollmentApproval.request != nil {
		t.Fatal("approval after the arming delay was not accepted")
	}
}

// The label and address are the client's, shown before the client is
// trusted, so they are drawn escaped: a right-to-left override or a C1
// control cannot rearrange or recolour the popup.
func TestEnrollmentPopupEscapesWhatTheClientSent(t *testing.T) {
	m := approvalTestModel(ViewClientEnrollmentPopup)
	m.enrollmentApproval.request = &PendingEnrollmentRequest{
		ID: "one", SSHFingerprint: "SHA256:one", Label: "ops\u202elaptop\u009b31m", RemoteAddr: "10.0.0.7:5122",
	}
	view := stripANSI(m.renderClientEnrollmentPopup())
	if strings.ContainsAny(view, "\u202e\u009b") {
		t.Fatalf("the popup draws the client's control characters raw:\n%q", view)
	}
	if !strings.Contains(view, `ops\u202elaptop\u009b31m`) {
		t.Fatalf("the popup does not show the label escaped:\n%q", view)
	}
}
