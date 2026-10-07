// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// An enrollment_changed notification re-fetches the Enrolled Clients lists
// whenever they are on screen or are the screen a popup will return to;
// elsewhere it only keeps listening, since the screen loads afresh when
// opened. The refresh is the pair of list requests plus the listener.
func TestEnrollmentChangedRefreshesClientsScreenOnly(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(Model) Model
		refresh bool
	}{
		{"enrolled clients", func(m Model) Model { m.viewState = ViewEnrolledClients; return m }, true},
		{"revoke confirm", func(m Model) Model { m.viewState = ViewRevokeClientConfirm; return m }, true},
		{"import key", func(m Model) Model { m.viewState = ViewImportClientKey; return m }, true},
		{"request popup over enrolled clients", func(m Model) Model {
			m.viewState = ViewEnrolledClients
			return updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
		}, true},
		{"key list", func(m Model) Model { m.viewState = ViewKeyList; return m }, false},
		{"request popup over key list", func(m Model) Model {
			m.viewState = ViewKeyList
			return updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.prepare(approvalTestModel(ViewKeyList))
			before := m.viewState
			next, cmd := m.Update(EnrollmentChangedMsg{Reason: "approved", Fingerprint: "SHA256:one"})
			got := next.(Model)
			if got.viewState != before {
				t.Fatalf("view changed from %v to %v", before, got.viewState)
			}
			want := 1
			if tt.refresh {
				want = 3
			}
			if n := batchSize(t, cmd); n != want {
				t.Fatalf("commands issued = %d, want %d", n, want)
			}
		})
	}
}

// Esc on a request popup raised over the Enrolled Clients screen returns to
// a list that already includes the deferred request: the enrollment_changed
// that followed the announcement refreshed it under the popup.
func TestDeferredRequestIsOnTheListUnderneath(t *testing.T) {
	m := approvalTestModel(ViewEnrolledClients)
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "enroll-1", SSHFingerprint: "SHA256:one"}})
	if m.viewState != ViewClientEnrollmentPopup {
		t.Fatalf("view = %v, want the request popup", m.viewState)
	}
	m = updateModel(t, m, EnrollmentChangedMsg{Reason: "requested", Fingerprint: "SHA256:one"})
	m = updateModel(t, m, PendingEnrollmentsListMsg{Requests: []protocol.PendingEnrollmentInfo{{Fingerprint: "SHA256:one"}}})
	m = updateModel(t, m, EnrolledKeysListMsg{})
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.viewState != ViewEnrolledClients {
		t.Fatalf("view after esc = %v, want enrolled clients", m.viewState)
	}
	if len(m.clients.pending) != 1 || m.clients.pending[0].Fingerprint != "SHA256:one" {
		t.Fatalf("pending under the popup = %+v, want the deferred request", m.clients.pending)
	}
}
