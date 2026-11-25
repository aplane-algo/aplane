// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// exportFollowerKey is a cosigner key that follows the node default: it has
// no document of its own, and may still have tokens.
const exportFollowerKey = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"

// exportPoliciesModel is the policies view of a cosigner node holding docs,
// with the context such a node sends: the built-in networks and assets.
func exportPoliciesModel(t *testing.T, docs map[string]string, order ...string) Model {
	t.Helper()
	summary := exportSummary(docs, order...)
	m := Model{viewState: ViewKeyList}
	next, _ := m.openPolicies()
	m = next.(Model)
	summary.ID = m.policies.pendingPolicyID
	next, _ = m.handlePolicyLoaded(PolicyLoadedMsg{Policy: summary})
	m = next.(Model)

	m = deliverPolicyContext(m, summary.PolicySetSHA256)
	if m.policies.snapshot == "" {
		t.Fatal("the context did not settle a snapshot")
	}
	return m
}

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
	return runExportWithTokens(t, m, dir, docs, nil)
}

// runExportWithTokens is runExport from a node whose token listing, which
// the export reads after the documents a selector a page, names the sources
// every selector in tokens has a token for; nil tokens is a node that will
// not say.
func runExportWithTokens(t *testing.T, m Model, dir string, docs map[string]string, tokens map[string][]string) (Model, tea.Cmd) {
	t.Helper()
	next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	m = next.(Model)
	if m.viewState != ViewPolicyExportForm || !strings.HasPrefix(m.policies.export.path, "~/policy-export-") {
		t.Fatalf("x: view %v path %q", m.viewState, m.policies.export.path)
	}
	m.policies.export.path = dir
	next, _ = m.handlePolicyExportFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	return answerExport(t, next.(Model), docs, tokens)
}

// answerExport answers each request of the export in progress as
// runExportWithTokens does, and returns the model and the write command.
func answerExport(t *testing.T, m Model, docs map[string]string, tokens map[string][]string) (Model, tea.Cmd) {
	t.Helper()
	var next tea.Model
	var cmd tea.Cmd
	selectors := slices.Sorted(maps.Keys(tokens))
	for m.policies.export.pendingID != "" {
		if m.policies.export.listingTokens {
			reply := protocol.SourceTokenListResultMessage{BaseMessage: protocol.BaseMessage{ID: m.policies.export.pendingID}}
			if tokens == nil {
				reply.Code, reply.Error = protocol.ErrCodeSignerLocked, "the signer is locked"
			} else {
				reply.Success = true
				if len(selectors) > 0 {
					listing := protocol.SourceTokenSelector{Selector: selectors[0]}
					for _, source := range tokens[selectors[0]] {
						listing.Tokens = append(listing.Tokens, protocol.SourceTokenInfo{Source: source, State: protocol.SourceTokenInUse})
					}
					reply.Selectors, selectors = []protocol.SourceTokenSelector{listing}, selectors[1:]
				}
				reply.Omitted = len(selectors)
			}
			var ok bool
			next, cmd, ok = m.handlePolicyExportSourceTokens(sourceTokenListMsg(reply))
			if !ok {
				t.Fatal("the export did not take its token listing")
			}
			m = next.(Model)
			continue
		}
		// The key requested is the one not yet fetched, in summary order.
		fetched := len(m.policies.export.docs)
		want := m.policies.policy.Documents[fetched].Key
		if got := m.policies.export.snapshot; got != m.policies.snapshot {
			t.Fatalf("export fetches against %q, want the summary's snapshot", got)
		}
		next, cmd = m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{
			BaseMessage: protocol.BaseMessage{ID: m.policies.export.pendingID}, Success: true, Key: want, Document: docs[want],
		}})
		m = next.(Model)
	}
	return m, cmd
}

func TestPolicyExportWritesEveryDocument(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{\"key\": \"default\"}\n", policyViewKeyA: "{\"key\": \"" + policyViewKeyA + "\"}\n"}
	m := exportPoliciesModel(t, docs, policy.DefaultKey, policyViewKeyA)
	dir := filepath.Join(t.TempDir(), "export")
	m, write := runExport(t, m, dir, docs)
	if m.policies.export.busy != "Writing policy files..." || len(m.policies.export.docs) != 2 {
		t.Fatalf("after fetching: busy %q, %d docs", m.policies.export.busy, len(m.policies.export.docs))
	}

	written := write().(PolicyExportWrittenMsg)
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
	selected, err := policyexport.Discover([]string{filepath.Join(dir, policy.DefaultKey+".json")}, "")
	if err != nil || selected == nil || selected.Export.Baseline.SnapshotSHA256 != m.policies.snapshot {
		t.Fatalf("the export's context = %+v, %v; want the snapshot it was read at", selected, err)
	}
}

// The export reads the node's whole token listing, a page at a time, and
// records the sources every selector has a token for, a key without a
// document of its own included.
func TestPolicyExportRecordsSourceTokenNames(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{\"key\": \"default\"}\n", policyViewKeyA: "{\"key\": \"" + policyViewKeyA + "\"}\n"}
	m := exportPoliciesModel(t, docs, policy.DefaultKey, policyViewKeyA)
	dir := filepath.Join(t.TempDir(), "export")
	tokens := map[string][]string{policyViewKeyA: {"screening"}, exportFollowerKey: {"ops"}}
	m, write := runExportWithTokens(t, m, dir, docs, tokens)
	written := write().(PolicyExportWrittenMsg)
	if written.Err != nil {
		t.Fatal(written.Err)
	}
	selected, err := policyexport.Discover([]string{filepath.Join(dir, policy.DefaultKey+".json")}, "")
	if err != nil || selected == nil {
		t.Fatalf("Discover() = %v, %v", selected, err)
	}
	if got := fmt.Sprint(selected.Export.SourceTokens); got != fmt.Sprint(tokens) {
		t.Fatalf("recorded names = %v", got)
	}
	next, _ := m.handlePolicyExportWritten(written)
	if status := next.(Model).policies.status; strings.Contains(status, "No source token names") {
		t.Fatalf("status = %q", status)
	}
}

// A node that will not name its tokens, as for a session without
// policy.update, still gets its documents exported; the export records no
// names and says so.
func TestPolicyExportWithoutTokenNamesSaysSo(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{}\n"}
	for name, refuse := range map[string]func(m Model) (tea.Model, tea.Cmd){
		"a refused listing": func(m Model) (tea.Model, tea.Cmd) {
			next, cmd, ok := m.failPendingPolicyExport(m.policies.export.pendingID, errors.New("authorization denied"))
			if !ok {
				t.Fatal("the refusal was not the export's")
			}
			return next, cmd
		},
		"a failed listing": func(m Model) (tea.Model, tea.Cmd) {
			next, cmd, ok := m.handlePolicyExportSourceTokens(sourceTokenListMsg{
				BaseMessage: protocol.BaseMessage{ID: m.policies.export.pendingID}, Code: protocol.ErrCodeSignerLocked, Error: "locked",
			})
			if !ok {
				t.Fatal("the reply was not the export's")
			}
			return next, cmd
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := exportPoliciesModel(t, docs, policy.DefaultKey)
			next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
			m = next.(Model)
			dir := filepath.Join(t.TempDir(), "export")
			m.policies.export.path = dir
			next, _ = m.handlePolicyExportFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
			m = next.(Model)
			next, _ = m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{
				BaseMessage: protocol.BaseMessage{ID: m.policies.export.pendingID}, Success: true, Key: policy.DefaultKey, Document: docs[policy.DefaultKey],
			}})
			m = next.(Model)
			if !m.policies.export.listingTokens {
				t.Fatal("a cosigner export did not ask for its token names")
			}
			next, write := refuse(m)
			m = next.(Model)
			written := write().(PolicyExportWrittenMsg)
			if written.Err != nil {
				t.Fatal(written.Err)
			}
			next, _ = m.handlePolicyExportWritten(written)
			if status := next.(Model).policies.status; !strings.Contains(status, "No source token names were recorded") {
				t.Fatalf("status = %q", status)
			}
			selected, err := policyexport.Discover([]string{filepath.Join(dir, policy.DefaultKey+".json")}, "")
			if err != nil || selected == nil || selected.Export.SourceTokens != nil {
				t.Fatalf("an export without token names = %+v, %v", selected, err)
			}
		})
	}
}

// A retry is an export of its own: a note an earlier attempt left, from a
// token listing the node refused, is not shown after one that recorded the
// names.
func TestPolicyExportRetryDropsTheEarlierAttemptsTokenNote(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{}\n"}
	m := exportPoliciesModel(t, docs, policy.DefaultKey)
	dir := filepath.Join(t.TempDir(), "export")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "occupied"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m, write := runExportWithTokens(t, m, dir, docs, nil)
	next, _ := m.handlePolicyExportWritten(write().(PolicyExportWrittenMsg))
	m = next.(Model)
	if m.viewState != ViewPolicyExportForm || m.policies.export.err == "" {
		t.Fatalf("the first attempt: view %v err %q; want the write refused", m.viewState, m.policies.export.err)
	}

	if err := os.Remove(filepath.Join(dir, "occupied")); err != nil {
		t.Fatal(err)
	}
	next, _ = m.handlePolicyExportFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m, write = answerExport(t, next.(Model), docs, map[string][]string{})
	next, _ = m.handlePolicyExportWritten(write().(PolicyExportWrittenMsg))
	if status := next.(Model).policies.status; !strings.Contains(status, "Exported 1 policy document(s)") || strings.Contains(status, "No source token names") {
		t.Fatalf("the retry: status = %q", status)
	}
}

func TestPolicyExportWaitsForTheContext(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{}\n"}
	m := exportPoliciesModel(t, docs, policy.DefaultKey)
	m.policies.snapshot = ""
	next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	m = next.(Model)
	m.policies.export.path = filepath.Join(t.TempDir(), "export")
	next, _ = m.handlePolicyExportFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if got := next.(Model); got.policies.export.pendingID != "" || !strings.Contains(got.policies.export.err, "still loading") {
		t.Fatalf("export state %+v, want it to wait for the context", got.policies.export)
	}
}

func TestPolicyExportRefusesAPolicyThatChanged(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{}\n", policyViewKeyA: "{\"a\": 1}\n"}
	m := exportPoliciesModel(t, docs, policy.DefaultKey, policyViewKeyA)
	dir := filepath.Join(t.TempDir(), "export")
	changed := map[string]string{policy.DefaultKey: docs[policy.DefaultKey], policyViewKeyA: "{\"a\": 2}\n"}
	m, write := runExport(t, m, dir, changed)
	written := write().(PolicyExportWrittenMsg)
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
	failed, _, ok := m.failPendingPolicyExport(id, errors.New("not connected"))
	if !ok || failed.policies.export.busy != "" || !strings.Contains(failed.policies.export.err, "not connected") {
		t.Fatalf("send failure: ok %v state %+v", ok, failed.policies.export)
	}
	if _, _, ok := m.failPendingPolicyExport("other", errors.New("x")); ok {
		t.Fatal("a failure for another request ended the export")
	}
}

func TestPolicyExportIsAdvertised(t *testing.T) {
	m := loadedPoliciesModel(exportSummary(map[string]string{policy.DefaultKey: "{}"}, policy.DefaultKey))
	if !strings.Contains(m.policiesFooterText(), "x: Export") {
		t.Fatal("the policies view does not advertise export")
	}
}

// TestPolicyExportEndsOnADaemonError: an error the daemon returns for the
// document request ends the export with the error shown; an error for any
// other request leaves it waiting.
func TestPolicyExportEndsOnADaemonError(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: "{}\n", policyViewKeyA: "{}\n"}
	m := exportPoliciesModel(t, docs, policy.DefaultKey, policyViewKeyA)
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

// A file loaded from an export is reviewed only while the node is still what
// was exported, as apadmin policy apply does; an unfinished export is
// refused at load.
func TestPolicyLoadFromAnExportComparesTheNode(t *testing.T) {
	docs := map[string]string{policy.DefaultKey: cosignerDefaultDoc(), policyViewKeyA: policyApplyCosignerDoc(policyViewKeyA, "")}
	m := exportPoliciesModel(t, docs, policy.DefaultKey, policyViewKeyA)
	dir := filepath.Join(t.TempDir(), "export")
	m, write := runExport(t, m, dir, docs)
	written := write().(PolicyExportWrittenMsg)
	if written.Err != nil {
		t.Fatal(written.Err)
	}
	next, _ := m.handlePolicyExportWritten(written)
	m = next.(Model)
	edited := filepath.Join(dir, policyViewKeyA+".json")
	if err := os.WriteFile(edited, []byte(policyApplyCosignerDoc(policyViewKeyA, `{"reject_clawback": true}`)), 0o600); err != nil {
		t.Fatal(err)
	}

	current, _ := submitPolicyApplyPath(t, m, edited)
	current = deliverPolicyCheck(current, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	if current.policies.apply.pendingDocumentID == "" || current.policies.apply.err != "" {
		t.Fatalf("a current export: apply %+v, want the review to go on", current.policies.apply)
	}

	moved := map[string]string{policy.DefaultKey: docs[policy.DefaultKey], policyViewKeyA: policyApplyCosignerDoc(policyViewKeyA, `{"reject_asset_close": true}`)}
	stale, _ := submitPolicyApplyPath(t, exportPoliciesModel(t, moved, policy.DefaultKey, policyViewKeyA), edited)
	stale = deliverPolicyCheck(stale, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	if stale.policies.apply.pendingDocumentID != "" || !strings.Contains(stale.policies.apply.err, "is stale: the node's policy changed") {
		t.Fatalf("a stale export: apply %+v, want it refused before review", stale.policies.apply)
	}

	if err := os.WriteFile(filepath.Join(dir, policyexport.ContextDir, policyexport.InProgressFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unfinished, _ := submitPolicyApplyPath(t, m, edited)
	if unfinished.policies.apply.pendingCheckID != "" || !strings.Contains(unfinished.policies.apply.err, "did not finish") {
		t.Fatalf("an unfinished export: apply %+v, want it refused at load", unfinished.policies.apply)
	}
}
