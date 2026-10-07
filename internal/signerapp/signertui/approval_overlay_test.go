// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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

// A signing request withdraws a pending client access request; its popup
// closes and the operator returns to the screen underneath.
func TestWithdrawnClientAccessRequestClosesItsPopup(t *testing.T) {
	m := approvalTestModel(ViewKeyDetails)
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "token-1"}})
	m = updateModel(t, m, ClientEnrollmentCanceledMsg{ID: "other", Reason: "preempted"})
	if m.viewState != ViewClientEnrollmentPopup || m.enrollmentApproval.request == nil {
		t.Fatalf("withdrawal for another request closed the popup: view %v", m.viewState)
	}
	m = updateModel(t, m, ClientEnrollmentCanceledMsg{ID: "token-1", Reason: "preempted"})
	if m.enrollmentApproval.request != nil || m.viewState != ViewKeyDetails {
		t.Fatalf("after withdrawal: view %v, request %+v; want key details and no pending request", m.viewState, m.enrollmentApproval.request)
	}
}
