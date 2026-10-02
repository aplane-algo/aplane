// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

const (
	policyViewKeyA = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	policyViewKeyB = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func loadedPoliciesModel(policy protocol.PolicyMessage) Model {
	m := Model{viewState: ViewKeyList}
	next, _ := m.openPolicies()
	m = next.(Model)
	next, _ = m.handlePolicyLoaded(PolicyLoadedMsg{Policy: policy})
	return next.(Model)
}

func TestKeyListPolicyShortcutOpensPolicies(t *testing.T) {
	m := Model{viewState: ViewKeyList, keylist: keyListState{keys: []KeyInfo{{Address: "ADDR", KeyType: "ed25519"}}}}
	next, cmd := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	got := next.(Model)
	if got.viewState != ViewPolicies || !got.policies.loading || got.policies.returnView != ViewKeyList || cmd == nil {
		t.Fatalf("after p: view %v loading %v return %v cmd %v", got.viewState, got.policies.loading, got.policies.returnView, cmd)
	}
	if !strings.Contains(stripANSI(m.View()), "p: Policies") {
		t.Fatal("key list does not advertise the policies shortcut")
	}
}

func TestAdminPanelPoliciesRowOpensPolicies(t *testing.T) {
	m := Model{viewState: ViewAdminPanel, admin: adminPanelState{editingRow: -1, settings: &AdminSettings{PassphraseMethod: "none", Theme: "auto"}}}
	for i, row := range m.adminRows() {
		if row.action == "open_policies" {
			m.admin.selectedRow = i
		}
	}
	next, _ := m.handleAdminPanelKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if next.(Model).viewState != ViewPolicies {
		t.Fatalf("view = %v, want ViewPolicies", next.(Model).viewState)
	}
}

func TestPoliciesViewListsCosignerKeysAndOpensDocuments(t *testing.T) {
	doc := fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"transfer_policy":{"routes":[]}}`, policyViewKeyA)
	m := loadedPoliciesModel(protocol.PolicyMessage{
		Success:         true,
		NodeRole:        "cosigner",
		Documents:       []protocol.PolicyDocumentWire{{Key: policyViewKeyA, Document: doc, SHA256: "0123456789abcdef0123", SignedAtUnix: 1700000000}},
		Keys:            []protocol.PolicyKeyStatusWire{{Key: policyViewKeyB, Status: "no_policy"}, {Key: policyViewKeyA, Status: "active"}},
		PolicySetSHA256: "set-digest",
	})
	rendered := stripANSI(m.renderPolicies())
	for _, want := range []string{policyViewKeyB + "  no policy (rejects every request)", policyViewKeyA + "  active", "applied 2023-11-14", "set-digest", "read-only"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("policies view missing %q:\n%s", want, rendered)
		}
	}

	// The first row has no document, so enter stays on the list.
	next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if next.(Model).viewState != ViewPolicies {
		t.Fatal("enter on a key without a policy left the list")
	}
	next, _ = m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyDown})
	next, _ = next.(Model).handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.viewState != ViewPolicyDocument || !strings.Contains(stripANSI(m.renderPolicyDocument()), `"format":"aplane.cosigner-policy.v1"`) {
		t.Fatalf("document view = %v:\n%s", m.viewState, m.renderPolicyDocument())
	}

	next, _ = m.handlePolicyDocumentKeys(tea.KeyMsg{Type: tea.KeyEsc})
	next, _ = next.(Model).handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if next.(Model).viewState != ViewKeyList {
		t.Fatalf("esc returned to %v, want ViewKeyList", next.(Model).viewState)
	}
}

func TestPoliciesViewShowsSignerDocumentAndErrors(t *testing.T) {
	m := loadedPoliciesModel(protocol.PolicyMessage{
		Success:   true,
		NodeRole:  "signer",
		Documents: []protocol.PolicyDocumentWire{{Document: "{\n  \"format\": \"aplane.signer-policy.v1\"\n}\n", SHA256: "abc"}},
	})
	if rows := m.policyRows(); len(rows) != 1 || rows[0].label != "policy.json" {
		t.Fatalf("signer rows = %+v", rows)
	}
	next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if lines := next.(Model).policyDocumentLines(); len(lines) != 3 {
		t.Fatalf("document lines = %q", lines)
	}

	failed := loadedPoliciesModel(protocol.PolicyMessage{Code: "policy_unavailable", Error: "policy is not loaded"})
	if !strings.Contains(stripANSI(failed.renderPolicies()), "Policy unavailable: policy is not loaded") {
		t.Fatalf("error view:\n%s", failed.renderPolicies())
	}
}

func TestPolicyDocumentScrollIsBounded(t *testing.T) {
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i)
	}
	m := loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer",
		Documents: []protocol.PolicyDocumentWire{{Document: strings.Join(lines, "\n")}}})
	m.height = 20
	m.viewState = ViewPolicyDocument
	for range 100 {
		next, _ := m.handlePolicyDocumentKeys(tea.KeyMsg{Type: tea.KeyPgDown})
		m = next.(Model)
	}
	if want := 50 - m.policyDocumentVisibleLines(); m.policies.scrollOffset != want {
		t.Fatalf("scroll offset = %d, want %d", m.policies.scrollOffset, want)
	}
	next, _ := m.handlePolicyDocumentKeys(tea.KeyMsg{Type: tea.KeyPgUp})
	for range 100 {
		next, _ = next.(Model).handlePolicyDocumentKeys(tea.KeyMsg{Type: tea.KeyUp})
	}
	if next.(Model).policies.scrollOffset != 0 {
		t.Fatalf("scroll offset = %d, want 0", next.(Model).policies.scrollOffset)
	}
}
