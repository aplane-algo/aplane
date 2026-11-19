// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
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

// Enrolled Clients is a top-level screen: c on the key list opens it, and
// esc returns to the key list. Settings no longer binds c.
func TestKeyListCShortcutOpensEnrolledClients(t *testing.T) {
	m := Model{viewState: ViewKeyList}
	next, cmd := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	got := next.(Model)
	if got.viewState != ViewEnrolledClients || !got.clients.loading || got.clients.returnView != ViewKeyList {
		t.Fatalf("viewState = %v clients = %+v, want the enrolled clients screen loading", got.viewState, got.clients)
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want the list request")
	}
	got = updateModel(t, got, tea.KeyMsg{Type: tea.KeyEsc})
	if got.viewState != ViewKeyList {
		t.Fatalf("view after esc = %v, want the key list", got.viewState)
	}

	admin := Model{viewState: ViewAdminPanel, admin: adminPanelState{editingRow: -1, settings: &AdminSettings{PassphraseMethod: "none", Theme: "auto"}}}
	next, _ = admin.handleAdminPanelKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if next.(Model).viewState != ViewAdminPanel {
		t.Fatalf("settings still binds c: view = %v", next.(Model).viewState)
	}
}

// The revoke dialog names the key by the label the client sent before it was
// trusted, so the label is drawn escaped there too: a right-to-left override
// or a C1 control cannot rearrange or recolour the dialog.
func TestRevokeDialogEscapesTheClientLabel(t *testing.T) {
	const label = "ops\u202elaptop\u009b31m"
	m := sizedForTest(t, Model{viewState: ViewEnrolledClients, connectionState: ConnectionConnected, clients: clientsState{
		keys: []protocol.EnrolledKeyInfo{{Fingerprint: "SHA256:one", Label: label, KeyType: "ssh-ed25519"}},
	}}, MinWidth, MinHeight)
	next, _ := m.handleEnrolledClientsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = next.(Model)
	if m.viewState != ViewRevokeClientConfirm {
		t.Fatalf("r opened %v, want the revoke dialog", m.viewState)
	}
	view := requireFits(t, m, MinWidth, MinHeight)
	if strings.ContainsAny(view, "\u202e\u009b") {
		t.Fatalf("the revoke dialog draws the client's control characters raw:\n%q", view)
	}
	if !strings.Contains(view, `Label: ops\u202elaptop\u009b31m`) {
		t.Fatalf("the revoke dialog does not show the label escaped:\n%q", view)
	}

	// The address a waiting request came from is drawn escaped on the list,
	// as it is on the popup.
	waiting := sizedForTest(t, Model{viewState: ViewEnrolledClients, connectionState: ConnectionConnected, clients: clientsState{
		pending: []protocol.PendingEnrollmentInfo{{Fingerprint: "SHA256:two", KeyType: "ssh-ed25519", RemoteAddr: "10.0.0.7\u009b31m"}},
	}}, MinWidth, MinHeight)
	if view := requireFits(t, waiting, MinWidth, MinHeight); strings.Contains(view, "\u009b") || !strings.Contains(view, `From:      10.0.0.7\u009b31m`) {
		t.Fatalf("the waiting request's address is not drawn escaped:\n%q", view)
	}
}
