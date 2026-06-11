// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"testing"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

func TestSignRequestCanceledClosesMatchingPopup(t *testing.T) {
	m := Model{
		viewState: ViewSigningPopup,
		signing: signingState{request: &PendingSignRequest{
			ID: "sign-1",
		}}, lastWarningGeneration: 2,
	}

	next, cmd := m.Update(SignRequestCanceledMsg{
		ID:     "sign-1",
		Reason: signerapproval.SignRequestCancelReasonClientCanceled,
	})
	got := next.(Model)
	if got.signing.request != nil {
		t.Fatalf("pendingSign = %#v, want nil", got.signing.request)
	}
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
	}
	if got.lastWarning != "Signing request canceled by requester" {
		t.Fatalf("lastWarning = %q, want requester cancellation", got.lastWarning)
	}
	if got.lastWarningGeneration != 3 {
		t.Fatalf("lastWarningGeneration = %d, want 3", got.lastWarningGeneration)
	}
	if cmd == nil {
		t.Fatal("Update returned nil cmd, want wait-for-message and warning-clear commands")
	}
	got, _ = updateForTest(t, got, clearWarningMsg{Generation: got.lastWarningGeneration})
	if got.lastWarning != "" {
		t.Fatalf("matching clear left warning = %q", got.lastWarning)
	}
}

func TestSignRequestCanceledIgnoresNonMatchingPopup(t *testing.T) {
	pending := &PendingSignRequest{ID: "sign-1"}
	m := Model{
		viewState: ViewSigningPopup,
		signing:   signingState{request: pending, focus: 1}, lastWarning: "previous",
		lastWarningGeneration: 7,
	}

	next, _ := m.Update(SignRequestCanceledMsg{
		ID:     "sign-2",
		Reason: signerapproval.SignRequestCancelReasonTimeout,
	})
	got := next.(Model)
	if got.signing.request != pending {
		t.Fatalf("pendingSign changed to %#v, want original", got.signing.request)
	}
	if got.viewState != ViewSigningPopup {
		t.Fatalf("viewState = %v, want ViewSigningPopup", got.viewState)
	}
	if got.lastWarning != "previous" || got.lastWarningGeneration != 7 {
		t.Fatalf("warning = %q generation %d, want unchanged", got.lastWarning, got.lastWarningGeneration)
	}
}
