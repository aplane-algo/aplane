// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// A list that could not be read is not an empty one: the screen says the
// list failed, and a list that arrives later replaces the error.

func TestFailedBackupListShowsTheErrorNotAnEmptyRepository(t *testing.T) {
	m := backupsModel()
	m.restore.backupsLoaded = false
	m, _ = update(t, m, BackupsListMsg{Error: "open backups: permission denied"})
	view := stripANSI(m.renderBackups())
	if !strings.Contains(view, "Backup list failed: open backups: permission denied") ||
		strings.Contains(view, "No backups yet") || strings.Contains(view, "0 backups") {
		t.Fatalf("a failed first list:\n%s", view)
	}

	listed := BackupInfo{FileName: "lab-signer.tar.gz", Size: 100}
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{listed}})
	m, _ = update(t, m, BackupsListMsg{Error: "read backups: input/output error"})
	view = stripANSI(m.renderBackups())
	if !strings.Contains(view, "Backup list failed: read backups: input/output error") ||
		!strings.Contains(view, "Showing the last list read.") || !strings.Contains(view, "lab-signer.tar.gz") ||
		strings.Contains(view, "1 backup on this signer") {
		t.Fatalf("a failed refresh:\n%s", view)
	}

	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{listed}})
	if view = stripANSI(m.renderBackups()); strings.Contains(view, "Backup list failed") || !strings.Contains(view, "1 backup on this signer") {
		t.Fatalf("a list after the failure:\n%s", view)
	}
}

func TestFailedCosignerListShowsTheErrorNotAnEmptyList(t *testing.T) {
	m := Model{viewState: ViewCosignerReferences, width: 100, height: 40}
	m, _ = update(t, m, CosignerReferencesMsg{Error: "list cosigner references: permission denied"})
	view := stripANSI(m.renderCosignerReferences())
	if !strings.Contains(view, "Cosigner references could not be listed: list cosigner references: permission denied") ||
		strings.Contains(view, "No cosigner references enrolled") {
		t.Fatalf("a failed list:\n%s", view)
	}
	// Nor does the Generate form's picker, which for an empty list goes
	// straight to a new import.
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{KeyType: secondPerKeyType, CosignerComponentKeyTypes: []string{"aplane.falcon1024.v1"}}})
	if _, errMsg := m.openCosignerPicker(secondPerKeyType, "cosigner"); !strings.Contains(errMsg, "could not be listed: list cosigner references: permission denied") {
		t.Fatalf("picker after a failed list: %q", errMsg)
	}

	m, _ = update(t, m, CosignerReferencesMsg{References: testCosignerReferences()})
	m, _ = update(t, m, CosignerReferencesMsg{Error: "list cosigner references: input/output error"})
	view = stripANSI(m.renderCosignerReferences())
	if !strings.Contains(view, "could not be listed: list cosigner references: input/output error") ||
		!strings.Contains(view, "Showing the last list read.") || !strings.Contains(view, "west") {
		t.Fatalf("a failed refresh:\n%s", view)
	}

	m, _ = update(t, m, CosignerReferencesMsg{References: testCosignerReferences()})
	if view = stripANSI(m.renderCosignerReferences()); strings.Contains(view, "could not be listed") {
		t.Fatalf("a list after the failure:\n%s", view)
	}
	if next, errMsg := m.openCosignerPicker(secondPerKeyType, "cosigner"); errMsg != "" || next.viewState != ViewCosignerPicker {
		t.Fatalf("picker after a list: view %v, error %q", next.viewState, errMsg)
	}
}

// A daemon error for the Policies summary, its context or a document (an
// authorization denial, a node with no runtime bound), or a failed send,
// reaches the screen waiting on it, which then shows it and can be left.
func TestPolicyReadFailuresSettleThePoliciesScreen(t *testing.T) {
	m := Model{viewState: ViewKeyList}
	next, cmd := m.openPolicies()
	m = next.(Model)
	if ids := sentRequestIDs(cmd); !slices.Contains(ids, m.policies.pendingPolicyID) || !slices.Contains(ids, m.policies.pendingContextID) {
		t.Fatalf("a failed send of the summary and context reads carries IDs %v", ids)
	}
	m, _ = update(t, m, ErrorMsg{ID: m.policies.pendingPolicyID, Error: errors.New("no runtime bound")})
	if view := stripANSI(m.renderPolicies()); m.policies.loading || !strings.Contains(view, "Policy unavailable: no runtime bound") {
		t.Fatalf("summary failure:\n%s", view)
	}
	if left, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyEsc}); left.(Model).viewState != ViewKeyList {
		t.Fatal("esc does not leave the Policies screen")
	}

	// The context read fails: apply and export say so instead of "still loading".
	m = loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer", Documents: []protocol.PolicyDocumentInfoWire{defaultDocInfo}})
	next, _ = m.requestPolicy()
	m = next.(Model)
	m, _ = update(t, m, ErrorMsg{ID: m.policies.pendingContextID, Error: errors.New("not authorized")})
	if problem := m.policyContextProblem(); !strings.Contains(problem, "could not be read: not authorized") {
		t.Fatalf("context failure: %q", problem)
	}
	m.policies.export.path = t.TempDir() + "/export"
	next, _ = m.startPolicyExport()
	if err := next.(Model).policies.export.err; !strings.Contains(err, "could not be read: not authorized") {
		t.Fatalf("export after a failed context read: %q", err)
	}
	next, _ = m.requestPolicy()
	m = next.(Model)
	m, _ = update(t, m, PolicyContextLoadedMsg{Context: PolicyContextMessage{BaseMessage: BaseMessage{ID: m.policies.pendingContextID}, Error: "context unavailable"}})
	if problem := m.policyContextProblem(); !strings.Contains(problem, "could not be read: context unavailable") {
		t.Fatalf("unsuccessful context reply: %q", problem)
	}

	// A document read fails.
	m = loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer", Documents: []protocol.PolicyDocumentInfoWire{defaultDocInfo}})
	next, cmd = m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if id := m.policies.pendingDocumentID; id == "" || !slices.Contains(sentRequestIDs(cmd), id) {
		t.Fatalf("a failed send of the document read carries IDs %v", sentRequestIDs(cmd))
	}
	m, _ = update(t, m, sendFailedMsg{ID: m.policies.pendingDocumentID, Error: errors.New("connection lost")})
	if view := stripANSI(m.renderPolicyDocument()); m.policies.docLoading || !strings.Contains(view, "Document unavailable: connection lost") {
		t.Fatalf("document failure:\n%s", view)
	}
}

func TestLibraryDetailsReadFailureLeavesLoading(t *testing.T) {
	m := Model{viewState: ViewTemplateLibrary, library: libraryState{templates: []protocol.LibraryTemplateInfo{{
		KeyType: "aplane.htlc.v1", TemplateType: "generic", SourcePath: "/library/aplane.htlc.v1.yaml",
	}}}}
	next, cmd := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	m = next.(Model)
	id := m.library.detailsRequestID
	if !m.library.detailsLoading || id == "" || !slices.Contains(sentRequestIDs(cmd), id) {
		t.Fatalf("details read: loading %v, id %q, sent %v", m.library.detailsLoading, id, sentRequestIDs(cmd))
	}
	m, _ = update(t, m, ErrorMsg{ID: id, Error: errors.New("not authorized")})
	if view := stripANSI(m.renderLibraryTemplateDetails()); m.library.detailsLoading || !strings.Contains(view, "not authorized") || strings.Contains(view, "Loading") {
		t.Fatalf("details failure:\n%s", view)
	}
}

func TestEnrolledClientsListFailuresAreShown(t *testing.T) {
	m := Model{viewState: ViewAdminPanel, width: 100, height: 40}
	next, cmd := m.openEnrolledClients()
	m = next.(Model)
	ids := sentRequestIDs(cmd)
	if !slices.Contains(ids, m.clients.keysListID) || !slices.Contains(ids, m.clients.pendingListID) {
		t.Fatalf("a failed send of the list reads carries IDs %v", ids)
	}
	m, _ = update(t, m, ErrorMsg{ID: m.clients.keysListID, Error: errors.New("not authorized")})
	m, _ = update(t, m, ErrorMsg{ID: m.clients.pendingListID, Error: errors.New("queue unreadable")})
	view := stripANSI(m.renderEnrolledClients())
	if m.clients.loading || strings.Contains(view, "Loading") ||
		!strings.Contains(view, "Enrolled client keys could not be listed: not authorized") ||
		!strings.Contains(view, "Enrollment requests could not be listed: queue unreadable") ||
		strings.Contains(view, "no enrolled client keys") || strings.Contains(view, "none. Clients request") {
		t.Fatalf("list failures:\n%s", view)
	}

	m, _ = update(t, m, EnrolledKeysListMsg{})
	m, _ = update(t, m, PendingEnrollmentsListMsg{})
	if view = stripANSI(m.renderEnrolledClients()); strings.Contains(view, "could not be listed") || !strings.Contains(view, "no enrolled client keys") {
		t.Fatalf("lists after the failures:\n%s", view)
	}
}
