// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

func exportInfo(key, text string) protocol.PolicyDocumentInfoWire {
	sum := sha256.Sum256([]byte(text))
	return protocol.PolicyDocumentInfoWire{Key: key, SHA256: hex.EncodeToString(sum[:]), Size: len(text)}
}

func exportSummary(docs map[string]string, order ...string) protocol.PolicyMessage {
	msg := protocol.PolicyMessage{Success: true, NodeRole: "cosigner"}
	var stored []policy.StoredDocument
	for _, key := range order {
		msg.Documents = append(msg.Documents, exportInfo(key, docs[key]))
		stored = append(stored, policy.StoredDocument{Key: key, Bytes: []byte(docs[key])})
		if key != policy.DefaultKey {
			msg.Keys = append(msg.Keys, protocol.PolicyKeyStatusWire{Key: key, Status: "own"})
		}
	}
	msg.PolicySetSHA256 = policy.PolicySetSHA256(stored)
	return msg
}

// runExport opens the export form, enters dir, then answers each document
// request from docs. It returns the model and the write command.
func runExport(t *testing.T, m Model, dir string, docs map[string]string) (Model, tea.Cmd) {
	t.Helper()
	next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	m = next.(Model)
	if m.viewState != ViewPolicyExportForm || !strings.HasPrefix(m.policies.export.path, "~/policy-export-") {
		t.Fatalf("x: view %v path %q", m.viewState, m.policies.export.path)
	}
	m.policies.export.path = dir
	next, _ = m.handlePolicyExportFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	var cmd tea.Cmd
	for m.policies.export.pendingID != "" {
		// The key requested is the one not yet fetched, in summary order.
		fetched := len(m.policies.export.docs)
		want := m.policies.policy.Documents[fetched].Key
		next, cmd = m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{
			BaseMessage: protocol.BaseMessage{ID: m.policies.export.pendingID}, Success: true, Key: want, Document: docs[want],
		}})
		m = next.(Model)
	}
	return m, cmd
}

func TestPolicyExportWritesEveryDocument(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{\"key\": \"default\"}\n", policyViewKeyA: "{\"key\": \"" + policyViewKeyA + "\"}\n"}
	m := loadedPoliciesModel(exportSummary(docs, policy.DefaultKey, policyViewKeyA))
	dir := filepath.Join(t.TempDir(), "export")
	m, _ = runExport(t, m, dir, docs)
	if m.policies.export.busy != "Writing policy files..." || len(m.policies.export.docs) != 2 {
		t.Fatalf("after fetching: busy %q, %d docs", m.policies.export.busy, len(m.policies.export.docs))
	}

	written := writePolicyExportCmd(m.policies.export.path, m.policies.export.docs, m.policies.export.setSHA256)().(PolicyExportWrittenMsg)
	next, _ := m.handlePolicyExportWritten(written)
	m = next.(Model)
	if m.viewState != ViewPolicies || !strings.Contains(m.policies.status, "Exported 2 policy document(s) to "+dir) || !strings.Contains(m.policies.status, "appolicy check") {
		t.Fatalf("after writing: view %v status %q err %v", m.viewState, m.policies.status, written.Err)
	}
	for key, text := range docs {
		data, err := os.ReadFile(filepath.Join(dir, key+".json"))
		if err != nil || string(data) != text {
			t.Fatalf("%s.json = %q, %v", key, data, err)
		}
	}
}

func TestPolicyExportRefusesAPolicyThatChanged(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{}\n", policyViewKeyA: "{\"a\": 1}\n"}
	m := loadedPoliciesModel(exportSummary(docs, policy.DefaultKey, policyViewKeyA))
	dir := filepath.Join(t.TempDir(), "export")
	changed := map[string]string{policy.DefaultKey: docs[policy.DefaultKey], policyViewKeyA: "{\"a\": 2}\n"}
	m, _ = runExport(t, m, dir, changed)
	written := writePolicyExportCmd(m.policies.export.path, m.policies.export.docs, m.policies.export.setSHA256)().(PolicyExportWrittenMsg)
	next, _ := m.handlePolicyExportWritten(written)
	m = next.(Model)
	if m.viewState != ViewPolicyExportForm || !strings.Contains(m.policies.export.err, "changed while it was being exported") {
		t.Fatalf("view %v err %q", m.viewState, m.policies.export.err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("a refused export created its directory")
	}
}

func TestPolicyExportStopsOnAnUnavailableDocumentOrSendFailure(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{}\n"}
	m := loadedPoliciesModel(exportSummary(docs, policy.DefaultKey))
	next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	m = next.(Model)
	next, _ = m.handlePolicyExportFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	id := m.policies.export.pendingID
	next, _ = m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{BaseMessage: protocol.BaseMessage{ID: id}, Error: "gone"}})
	if got := next.(Model); got.policies.export.busy != "" || !strings.Contains(got.policies.export.err, "gone") {
		t.Fatalf("unavailable document: busy %q err %q", got.policies.export.busy, got.policies.export.err)
	}

	next, _ = m.handlePolicyExportFormKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if got := next.(Model); got.viewState != ViewPolicies {
		t.Fatalf("esc during the fetch: view %v", got.viewState)
	}
	failed, ok := m.failPendingPolicyExport(id, errors.New("not connected"))
	if !ok || failed.policies.export.busy != "" || !strings.Contains(failed.policies.export.err, "not connected") {
		t.Fatalf("send failure: ok %v state %+v", ok, failed.policies.export)
	}
	if _, ok := m.failPendingPolicyExport("other", errors.New("x")); ok {
		t.Fatal("a failure for another request ended the export")
	}
}

func TestPolicyExportIsAdvertised(t *testing.T) {
	m := loadedPoliciesModel(exportSummary(map[string]string{policy.DefaultKey: "{}"}, policy.DefaultKey))
	if !strings.Contains(m.policiesFooterText(), "x: Export") || !strings.Contains(stripANSI(m.renderPolicies()), "x exports the policy") {
		t.Fatal("the policies view does not advertise export")
	}
}

// TestPolicyExportEndsOnADaemonError: an error the daemon returns for the
// document request ends the export with the error shown; an error for any
// other request leaves it waiting.
func TestPolicyExportEndsOnADaemonError(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{}\n", policyViewKeyA: "{}\n"}
	m := loadedPoliciesModel(exportSummary(docs, policy.DefaultKey, policyViewKeyA))
	next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	next, _ = next.(Model).handlePolicyExportFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	id := m.policies.export.pendingID
	if id == "" || m.policies.export.busy == "" {
		t.Fatalf("export did not start: %+v", m.policies.export)
	}

	next, _ = m.Update(ErrorMsg{ID: "list-keys-1", Error: errors.New("list failed")})
	if got := next.(Model); got.policies.export.pendingID != id || got.policies.export.busy == "" {
		t.Fatalf("an unrelated error ended the export: %+v", got.policies.export)
	}

	next, _ = m.Update(ErrorMsg{ID: id, Error: errors.New("authorization denied")})
	got := next.(Model)
	if got.viewState != ViewPolicyExportForm || got.policies.export.pendingID != "" || got.policies.export.busy != "" ||
		!strings.Contains(got.policies.export.err, "authorization denied") {
		t.Fatalf("after the daemon error: view %v export %+v", got.viewState, got.policies.export)
	}
	if !strings.Contains(stripANSI(got.renderPolicyExportForm()), "authorization denied") {
		t.Fatal("the export form does not show the error")
	}
}
