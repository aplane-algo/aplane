// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func updateModel(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	next, _ := m.Update(msg)
	got, ok := next.(Model)
	if !ok {
		t.Fatalf("Update(%T) returned %T", msg, next)
	}
	return got
}

func approvalTestModel(view ViewState) Model {
	return Model{viewState: view, connectionState: ConnectionConnected, width: 100, height: 40}
}

// A result that arrives while an approval popup is open must not replace the
// popup; answering returns to the screen the result selected.
func TestSigningPopupStaysOnTopOfBackgroundResults(t *testing.T) {
	m := approvalTestModel(ViewGenerating)
	m = updateModel(t, m, SignRequestReceivedMsg{Request: PendingSignRequest{ID: "sign-1"}})
	if m.viewState != ViewSigningPopup {
		t.Fatalf("view after sign request = %v, want the signing popup", m.viewState)
	}
	m = updateModel(t, m, GenerateResultMsg{Success: true, Address: "ADDR", KeyType: "ed25519"})
	if m.viewState != ViewSigningPopup || m.signing.request == nil {
		t.Fatalf("generate result replaced the signing popup: view %v", m.viewState)
	}
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.viewState != ViewGenerateDisplay || m.signing.request != nil {
		t.Fatalf("after answering: view %v, want the generate result underneath", m.viewState)
	}
}

func TestCanceledSigningRequestReturnsToScreenUnderneath(t *testing.T) {
	m := approvalTestModel(ViewBackupConfirm)
	m = updateModel(t, m, SignRequestReceivedMsg{Request: PendingSignRequest{ID: "sign-1"}})
	m = updateModel(t, m, SignRequestCanceledMsg{ID: "sign-1"})
	if m.viewState != ViewBackupConfirm || m.signing.request != nil {
		t.Fatalf("after cancel: view %v, want the backup form", m.viewState)
	}

	// A cancel for a request that is not open leaves the operator in place.
	m = updateModel(t, m, SignRequestCanceledMsg{ID: "other"})
	if m.viewState != ViewBackupConfirm {
		t.Fatalf("unrelated cancel moved the operator to %v", m.viewState)
	}
}

// Handlers that act on the current screen see the screen under the popup.
func TestBackgroundFailureUnderPopupReachesTheOperationInProgress(t *testing.T) {
	m := approvalTestModel(ViewImportParams)
	id := m.beginOperation(ViewImporting)
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "token-1"}})
	m = updateModel(t, m, ErrorMsg{ID: id, Error: errors.New("authorization denied")})
	if m.viewState != ViewClientEnrollmentPopup {
		t.Fatalf("error replaced the enrollment popup: view %v", m.viewState)
	}
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.viewState != ViewImportParams || m.forms.importError != "authorization denied" {
		t.Fatalf("after answering: view %v error %q, want the import form with the failure", m.viewState, m.forms.importError)
	}
}

func TestSecondApprovalShowsAfterFirstIsAnswered(t *testing.T) {
	m := approvalTestModel(ViewKeyDetails)
	m = updateModel(t, m, SignRequestReceivedMsg{Request: PendingSignRequest{ID: "sign-1"}})
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "token-1"}})
	if m.viewState != ViewSigningPopup {
		t.Fatalf("view %v, want the signing popup kept in front", m.viewState)
	}
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.viewState != ViewClientEnrollmentPopup {
		t.Fatalf("after answering the signing request: view %v, want the enrollment popup", m.viewState)
	}
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.viewState != ViewKeyDetails {
		t.Fatalf("after answering both: view %v, want key details", m.viewState)
	}
}

// apsigner rejects pending approvals when the session ends or the signer
// locks, so their popups must not come back.
func TestSessionEndAndLockDropPendingApprovals(t *testing.T) {
	for name, msg := range map[string]tea.Msg{
		"disconnect":    DisconnectedMsg{},
		"reconnecting":  ReconnectingMsg{},
		"auth required": AuthRequiredMsg{},
		"displaced":     DisplacedMsg{Reason: "replaced"},
		"locked":        SignerStatusMsg{State: "locked"},
	} {
		m := approvalTestModel(ViewKeyList)
		m = updateModel(t, m, SignRequestReceivedMsg{Request: PendingSignRequest{ID: "sign-1"}})
		m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "token-1"}})
		m = updateModel(t, m, msg)
		if m.signing.request != nil || m.enrollmentApproval.request != nil || isApprovalView(m.viewState) {
			t.Errorf("%s left an approval pending: view %v", name, m.viewState)
		}
	}
}

func TestUntypedFailureLeavesProgressScreens(t *testing.T) {
	for progress, want := range map[ViewState]ViewState{
		ViewGenerating:         ViewGenerateForm,
		ViewImporting:          ViewImportParams,
		ViewDeleting:           ViewDeleteConfirm,
		ViewTemplateInstalling: ViewTemplateInstallConfirm,
		ViewBackingUp:          ViewBackupConfirm,
	} {
		m := approvalTestModel(ViewKeyList)
		id := m.beginOperation(progress)
		m = updateModel(t, m, ErrorMsg{ID: id, Error: errors.New("cannot decode result")})
		if m.viewState != want {
			t.Errorf("failure on %v: view %v, want %v", progress, m.viewState, want)
		}
	}
}

// An error for another request, such as a background key-list refresh, must
// not fail the operation in progress: leaving its screen would invite a second
// submission while the first still runs.
func TestUnrelatedErrorKeepsOperationInProgress(t *testing.T) {
	m := approvalTestModel(ViewGenerateForm)
	m.beginOperation(ViewGenerating)
	for _, id := range []string{"", "keys-1"} {
		m = updateModel(t, m, ErrorMsg{ID: id, Error: errors.New("list keys failed")})
		if m.viewState != ViewGenerating {
			t.Fatalf("error for request %q left the generate progress screen: view %v", id, m.viewState)
		}
	}
	m = updateModel(t, m, GenerateResultMsg{Success: true, Address: "ADDR", KeyType: "ed25519"})
	if m.viewState != ViewGenerateDisplay {
		t.Fatalf("view after the generate result = %v, want the result", m.viewState)
	}
}

// Enrollment requests announced while one is on screen wait their turn; a
// request announced twice (as happens at login) is shown once.
func TestEnrollmentRequestsQueueBehindThePopup(t *testing.T) {
	m := approvalTestModel(ViewKeyDetails)
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-2", SSHFingerprint: "SHA256:two"}})
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	if m.viewState != ViewClientEnrollmentPopup || m.enrollmentApproval.request == nil || m.enrollmentApproval.request.ID != "enroll-1" {
		t.Fatalf("first request is not on screen: view %v request %+v", m.viewState, m.enrollmentApproval.request)
	}
	if len(m.enrollmentApproval.queue) != 1 || m.enrollmentApproval.queue[0].ID != "enroll-2" {
		t.Fatalf("queue = %+v, want only enroll-2", m.enrollmentApproval.queue)
	}
	if !m.nextEnrollmentRequest() || m.enrollmentApproval.request.ID != "enroll-2" || len(m.enrollmentApproval.queue) != 0 {
		t.Fatalf("after answering: request %+v queue %+v", m.enrollmentApproval.request, m.enrollmentApproval.queue)
	}
	if m.nextEnrollmentRequest() || m.enrollmentApproval.request != nil {
		t.Fatalf("queue drained but a request remains: %+v", m.enrollmentApproval.request)
	}
}

// A request answered from the Enrolled Clients list is not shown again by a
// later announcement (a login replay), and one answered from the popup is
// dropped from the popup queue; the signer's result settles the answer so
// a genuinely new request for the same key shows afterwards.
func TestAnsweredEnrollmentRequestIsNotShownAgain(t *testing.T) {
	m := approvalTestModel(ViewEnrolledClients)
	m.clients.pending = []protocol.PendingEnrollmentInfo{{Fingerprint: "SHA256:one"}}
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	if m.viewState != ViewEnrolledClients || m.enrollmentApproval.request != nil {
		t.Fatalf("a replay of an answered request was shown: view %v request %+v", m.viewState, m.enrollmentApproval.request)
	}
	m = updateModel(t, m, ApproveEnrollmentResultMsg{Success: true, Fingerprint: "SHA256:one"})
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	if m.viewState != ViewClientEnrollmentPopup {
		t.Fatalf("a new request after the answer settled was not shown: view %v", m.viewState)
	}

	// From the popup: answering one request drops its other announcements
	// from the queue, and the next distinct request follows.
	m = approvalTestModel(ViewKeyList)
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	m.enrollmentApproval.queue = []PendingEnrollmentRequest{
		{ID: "enroll-1", SSHFingerprint: "SHA256:one"},
		{ID: "enroll-2", SSHFingerprint: "SHA256:two"},
	}
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if m.enrollmentApproval.request == nil || m.enrollmentApproval.request.ID != "enroll-2" || len(m.enrollmentApproval.queue) != 0 {
		t.Fatalf("after answering enroll-1: request %+v queue %+v", m.enrollmentApproval.request, m.enrollmentApproval.queue)
	}
}

// The signer's answer to a popup approval reaches the operator wherever
// they are: a failure is never left on a status line they are not looking
// at.
func TestEnrollmentAnswerFromPopupIsReported(t *testing.T) {
	m := approvalTestModel(ViewKeyList)
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if m.viewState != ViewKeyList {
		t.Fatalf("view after answering = %v, want the key list", m.viewState)
	}
	m = updateModel(t, m, ApproveEnrollmentResultMsg{Success: false, Error: "registry not durable", Fingerprint: "SHA256:one"})
	if !strings.Contains(m.lastWarning, "Approval of SHA256:one failed: registry not durable") {
		t.Fatalf("lastWarning = %q, want the failed approval reported", m.lastWarning)
	}
	m = updateModel(t, m, RejectEnrollmentResultMsg{Success: true, Fingerprint: "SHA256:two"})
	if !strings.Contains(m.lastWarning, "Enrollment request for SHA256:two rejected") {
		t.Fatalf("lastWarning = %q, want the rejection reported", m.lastWarning)
	}

	// On the Enrolled Clients screen the status line is the place.
	m = approvalTestModel(ViewEnrolledClients)
	m = updateModel(t, m, ApproveEnrollmentResultMsg{Success: false, Error: "boom", Fingerprint: "SHA256:one"})
	if m.clients.status != "Approval of SHA256:one failed: boom" || m.lastWarning != "" {
		t.Fatalf("status = %q, warning = %q", m.clients.status, m.lastWarning)
	}
}

// Esc on the enrollment popup defers the request instead of rejecting it:
// nothing is sent, the request stays in the signer's queue (so a later
// announcement shows it again), the next waiting request takes the popup,
// and the last Esc returns to the screen underneath.
func TestEscDefersEnrollmentRequest(t *testing.T) {
	m := approvalTestModel(ViewKeyDetails)
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-2", SSHFingerprint: "SHA256:two"}})

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)
	if m.viewState != ViewClientEnrollmentPopup || m.enrollmentApproval.request == nil || m.enrollmentApproval.request.ID != "enroll-2" {
		t.Fatalf("after deferring enroll-1: view %v request %+v", m.viewState, m.enrollmentApproval.request)
	}
	if len(m.enrollmentApproval.answering) != 0 {
		t.Fatalf("deferring recorded an answer in flight: %v", m.enrollmentApproval.answering)
	}
	_ = cmd

	next, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)
	if m.viewState != ViewKeyDetails || m.enrollmentApproval.request != nil || cmd != nil {
		t.Fatalf("after deferring the last request: view %v request %+v cmd %v", m.viewState, m.enrollmentApproval.request, cmd)
	}
	if len(m.enrollmentApproval.answering) != 0 {
		t.Fatalf("deferring recorded an answer in flight: %v", m.enrollmentApproval.answering)
	}

	// A deferred request is still waiting at the signer; its next
	// announcement (a login replay, or the client asking again) shows it.
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	if m.viewState != ViewClientEnrollmentPopup || m.enrollmentApproval.request == nil || m.enrollmentApproval.request.ID != "enroll-1" {
		t.Fatalf("deferred request announced again was not shown: view %v request %+v", m.viewState, m.enrollmentApproval.request)
	}

	// In recovery, closing the popup returns to the blocking recovery screen.
	m.signerState = signerRuntimeRecovery
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.viewState != ViewStoreRecovery || m.enrollmentApproval.request != nil {
		t.Fatalf("deferring in recovery: view %v request %+v", m.viewState, m.enrollmentApproval.request)
	}

	// Esc on the signing popup still rejects: a signing client is waiting.
	m = approvalTestModel(ViewKeyList)
	m = updateModel(t, m, SignRequestReceivedMsg{Request: PendingSignRequest{ID: "sign-1"}})
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.viewState != ViewKeyList || m.signing.request != nil {
		t.Fatalf("esc on the signing popup: view %v request %+v", m.viewState, m.signing.request)
	}
}
