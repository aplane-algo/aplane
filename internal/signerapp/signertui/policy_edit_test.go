// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyreview"
	tea "github.com/charmbracelet/bubbletea"
)

func pressPolicyKey(t *testing.T, m Model, key string) (Model, tea.Cmd) {
	t.Helper()
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	switch key {
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "ctrl+s":
		msg = tea.KeyMsg{Type: tea.KeyCtrlS}
	case "space":
		msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	var next tea.Model
	var cmd tea.Cmd
	switch m.viewState {
	case ViewPolicies:
		next, cmd = m.handlePoliciesKeys(msg)
	case ViewPolicyDocument:
		next, cmd = m.handlePolicyDocumentKeys(msg)
	case ViewPolicyEdit:
		next, cmd = m.handlePolicyEditKeys(msg)
	case ViewPolicyApplyReview:
		next, cmd = m.handlePolicyApplyReviewKeys(msg)
	default:
		t.Fatalf("no policy key handler for view %v", m.viewState)
	}
	return next.(Model), cmd
}

func policyEditText(m Model) string {
	return m.policies.apply.edit.input.Value()
}

func setPolicyEditText(m Model, text string) Model {
	m.policies.apply.edit.input.SetValue(text)
	return m
}

// A cosigner key with no policy opens on the starting document's template,
// and the edit goes through the same check, review, and apply as a loaded
// file.
func TestPolicyEditStartsKeyWithoutPolicyFromLockedDocument(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, cmd := pressPolicyKey(t, m, "e")
	if m.viewState != ViewPolicyEdit || !m.policies.apply.edit.isNew || m.policies.apply.edit.key != policyViewKeyA || cmd != nil {
		t.Fatalf("e: view %v edit %+v cmd %v, want the editor on a new document without a request", m.viewState, m.policies.apply.edit, cmd)
	}
	// The editor opens on the annotated template, which strips to the
	// starting document.
	template, err := policyreview.CosignerTemplate(policyViewKeyA)
	if err != nil {
		t.Fatal(err)
	}
	if got := policyEditText(m); got != strings.TrimRight(template, "\n") || !m.policies.apply.edit.annotated {
		t.Fatalf("editor text = %q, want the cosigner template", got)
	}
	rendered := stripANSI(m.renderPolicyEdit())
	for _, want := range []string{"Edit Policy", "cosigner key " + policyViewKeyA, "No policy yet", "remove //", "// Lines starting with //"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("editor missing %q:\n%s", want, rendered)
		}
	}
	if footer := m.policyEditFooterText(); !strings.Contains(footer, "ctrl+s: Check and review") {
		t.Fatalf("editor footer = %q", footer)
	}

	// Typed keys reach the text, including space, which arrives as its own key.
	m, _ = pressPolicyKey(t, m, "space")
	if got := policyEditText(m); !strings.HasPrefix(got, " {") {
		t.Fatalf("typed space did not reach the editor: %q", got)
	}

	m, cmd = pressPolicyKey(t, m, "ctrl+s")
	apply := m.policies.apply
	if apply.pendingCheckID == "" || apply.busy == "" || cmd == nil || apply.doc.Key != policyViewKeyA || apply.file != policyViewKeyA+".json" {
		t.Fatalf("ctrl+s: apply %+v cmd %v, want a check of the edited document", apply, cmd)
	}
	if _, err := policy.DecodeCosignerPolicyV1([]byte(apply.doc.Document), policyViewKeyA); err != nil {
		t.Fatalf("submitted document does not decode: %v\n%s", err, apply.doc.Document)
	}
	locked, err := policy.StartingCosignerDocumentV1(policyViewKeyA)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(apply.doc.Document, "//") || !policyTextEquivalent(locked, apply.doc.Document) {
		t.Fatalf("submitted document = %q, want the starting document without comments", apply.doc.Document)
	}

	m = deliverPolicyCheck(m, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	if m.viewState != ViewPolicyApplyReview {
		t.Fatalf("check: view %v apply %+v, want the review", m.viewState, m.policies.apply)
	}
	rendered = stripANSI(m.renderPolicyApplyReview())
	for _, want := range []string{"loosened", "new policy", "stores the edited text exactly"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("review missing %q:\n%s", want, rendered)
		}
	}
	if footer := m.policyApplyFooterText(); !strings.Contains(footer, "y: Apply") || !strings.Contains(footer, "Back to editor") {
		t.Fatalf("review footer = %q", footer)
	}

	// Declining returns to the editor with the text intact.
	edited := policyEditText(m)
	back, _ := pressPolicyKey(t, m, "n")
	if back.viewState != ViewPolicyEdit || policyEditText(back) != edited || len(back.policies.apply.diffLines) != 0 {
		t.Fatalf("n: view %v text %q, want the editor with the text kept", back.viewState, policyEditText(back))
	}

	m, cmd = pressPolicyKey(t, m, "y")
	if !m.policies.apply.applying || m.policies.apply.pendingApplyID == "" || cmd == nil {
		t.Fatalf("y: apply state %+v cmd %v", m.policies.apply, cmd)
	}
	next, _ := m.handlePolicyApplyResult(PolicyApplyResultMsg{Result: protocol.ApplyPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.apply.pendingApplyID},
		Success:     true,
		Policy:      &protocol.PolicyMessage{Success: true, GenerationID: "gen-7"},
	}})
	m = next.(Model)
	if m.viewState != ViewPolicies || m.policies.apply.edit.active || m.policies.status != "Applied "+policyViewKeyA+".json as generation gen-7" {
		t.Fatalf("applied: view %v status %q edit %+v", m.viewState, m.policies.status, m.policies.apply.edit)
	}
}

func TestPolicyEditLoadsActiveDocumentAndLaysItOut(t *testing.T) {
	m := cosignerPoliciesModel("active", protocol.PolicyDocumentInfoWire{Key: policyViewKeyA, SHA256: "abc", Size: 10})
	m.width, m.height = 120, 40
	m, cmd := pressPolicyKey(t, m, "e")
	edit := m.policies.apply.edit
	if m.viewState != ViewPolicyEdit || !edit.loading || edit.pendingDocumentID == "" || cmd == nil {
		t.Fatalf("e: view %v edit %+v cmd %v, want a document request", m.viewState, edit, cmd)
	}
	if !strings.Contains(stripANSI(m.renderPolicyEdit()), "Loading document") {
		t.Fatal("editor does not show loading")
	}
	compact := policyApplyCosignerDoc(policyViewKeyA, `"reject_clawback":true,`)
	next, _ := m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{
		BaseMessage: protocol.BaseMessage{ID: edit.pendingDocumentID}, Success: true, Key: policyViewKeyA, Document: compact,
	}})
	m = next.(Model)
	text := policyEditText(m)
	if m.policies.apply.edit.loading || m.policies.apply.edit.isNew || !strings.Contains(text, "\n  \"reject_clawback\": true,\n") {
		t.Fatalf("loaded: edit %+v text %q, want the stored document indented", m.policies.apply.edit, text)
	}

	// An unchanged document closes on the first esc.
	closed, _ := pressPolicyKey(t, m, "esc")
	if closed.viewState != ViewPolicies || closed.policies.apply.edit.active {
		t.Fatalf("esc: view %v, want the list", closed.viewState)
	}

	// The check loads the active document so the review shows field changes.
	m = setPolicyEditText(m, strings.Replace(text, `"reject_clawback": true`, `"reject_clawback": false`, 1))
	m, _ = pressPolicyKey(t, m, "ctrl+s")
	m = deliverPolicyCheck(m, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	if m.viewState != ViewPolicyEdit || m.policies.apply.pendingDocumentID == "" {
		t.Fatalf("check: view %v apply %+v, want the active document requested", m.viewState, m.policies.apply)
	}
	next, _ = m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.apply.pendingDocumentID}, Success: true, Key: policyViewKeyA, Document: compact,
	}})
	m = next.(Model)
	if rendered := stripANSI(m.renderPolicyApplyReview()); m.viewState != ViewPolicyApplyReview || !strings.Contains(rendered, "/reject_clawback") {
		t.Fatalf("review: view %v\n%s", m.viewState, rendered)
	}
}

func TestPolicyEditKeepsTextThroughErrors(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, _ = pressPolicyKey(t, m, "e")

	// A syntax error is reported with its position and sends nothing.
	broken := "{\n  \"format\": \"aplane.cosigner-policy.v1\",\n  \"key\": oops\n}"
	m = setPolicyEditText(m, broken)
	m, cmd := pressPolicyKey(t, m, "ctrl+s")
	if cmd != nil || m.policies.apply.pendingCheckID != "" || !strings.Contains(m.policies.apply.err, "Invalid JSON at line 3, column") {
		t.Fatalf("syntax error: err %q cmd %v", m.policies.apply.err, cmd)
	}
	if policyEditText(m) != broken || m.viewState != ViewPolicyEdit {
		t.Fatalf("syntax error changed the text or left the editor: %q", policyEditText(m))
	}
	if rendered := stripANSI(m.renderPolicyEdit()); !strings.Contains(rendered, "Invalid JSON at line 3") {
		t.Fatalf("editor does not show the syntax error:\n%s", rendered)
	}

	// The editor changes one key's policy; it cannot be pointed at another.
	m = setPolicyEditText(m, policyApplyCosignerDoc(policyViewKeyB, ""))
	m, cmd = pressPolicyKey(t, m, "ctrl+s")
	if cmd != nil || !strings.Contains(m.policies.apply.err, `"key" field must stay `+policyViewKeyA) {
		t.Fatalf("changed key: err %q cmd %v", m.policies.apply.err, cmd)
	}

	// A document the node rejects keeps the editor open with its problems.
	candidate := policyApplyCosignerDoc(policyViewKeyA, `"max_fee_microalgos":"-1",`)
	m = setPolicyEditText(m, candidate)
	m, _ = pressPolicyKey(t, m, "ctrl+s")
	m = deliverPolicyCheck(m, protocol.CheckPolicyResultMessage{Success: true, Valid: false,
		Errors: []protocol.PolicyProblemWire{{Key: policyViewKeyA, Pointer: "/max_fee_microalgos", Message: "amount must be a non-negative integer"}}})
	if m.viewState != ViewPolicyEdit || m.policies.apply.busy != "" || policyEditText(m) != candidate {
		t.Fatalf("rejected: view %v busy %q text %q", m.viewState, m.policies.apply.busy, policyEditText(m))
	}
	rendered := stripANSI(m.renderPolicyEdit())
	// Long problems wrap rather than lose their explanation.
	for _, want := range []string{"Policy is invalid", "/max_fee_microalgos", "amount must be a non-negative", "integer"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("editor missing %q:\n%s", want, rendered)
		}
	}
}

func TestPolicyEditDiscardNeedsSecondEsc(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, _ = pressPolicyKey(t, m, "e")
	m, _ = pressPolicyKey(t, m, "x")
	if !strings.HasPrefix(policyEditText(m), "x{") {
		t.Fatalf("typed rune did not reach the editor: %q", policyEditText(m))
	}

	m, _ = pressPolicyKey(t, m, "esc")
	if m.viewState != ViewPolicyEdit || !m.policies.apply.edit.confirmDiscard {
		t.Fatalf("first esc: view %v edit %+v, want a discard confirmation", m.viewState, m.policies.apply.edit)
	}
	if rendered := stripANSI(m.renderPolicyEdit()); !strings.Contains(rendered, "Discard your changes?") {
		t.Fatalf("editor does not ask before discarding:\n%s", rendered)
	}
	if footer := m.policyEditFooterText(); !strings.Contains(footer, "Discard changes") {
		t.Fatalf("discard footer = %q", footer)
	}

	// Any other key keeps editing.
	kept, _ := pressPolicyKey(t, m, "y")
	if kept.viewState != ViewPolicyEdit || kept.policies.apply.edit.confirmDiscard || !strings.HasPrefix(policyEditText(kept), "xy{") {
		t.Fatalf("other key: view %v edit confirm %v text %q", kept.viewState, kept.policies.apply.edit.confirmDiscard, policyEditText(kept))
	}

	discarded, _ := pressPolicyKey(t, m, "esc")
	if discarded.viewState != ViewPolicies || discarded.policies.apply.edit.active {
		t.Fatalf("second esc: view %v, want the list", discarded.viewState)
	}
}

func TestPolicyEditRefusesKeyTheNodeDoesNotHold(t *testing.T) {
	m := cosignerPoliciesModel("key_not_held", protocol.PolicyDocumentInfoWire{Key: policyViewKeyA, SHA256: "abc", Size: 10})
	m, cmd := pressPolicyKey(t, m, "e")
	if m.viewState != ViewPolicies || cmd != nil || !strings.Contains(m.policies.status, "does not hold cosigner key "+policyViewKeyA) {
		t.Fatalf("e: view %v status %q cmd %v", m.viewState, m.policies.status, cmd)
	}
}

func TestPolicyEditSignerDocumentFromDocumentView(t *testing.T) {
	m := loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer",
		Documents: []protocol.PolicyDocumentInfoWire{{SHA256: "abc", Size: 34}}, PolicySetSHA256: "set-digest"})
	m.width, m.height = 120, 40
	m = openLoadedDocument(t, m, protocol.PolicyDocumentMessage{Success: true, Document: string(policy.InitialSignerPolicy)})
	if footer := m.policiesFooterText(); !strings.Contains(footer, "e: Edit") {
		t.Fatalf("document footer = %q", footer)
	}
	m, cmd := pressPolicyKey(t, m, "e")
	edit := m.policies.apply.edit
	if m.viewState != ViewPolicyEdit || edit.key != "" || edit.isNew || edit.loading || cmd != nil {
		t.Fatalf("e: view %v edit %+v cmd %v", m.viewState, edit, cmd)
	}
	// The initial signer policy is the starting document, so it opens as
	// its annotated template.
	if !edit.annotated || policyEditText(m) != strings.TrimRight(policyreview.SignerTemplate(), "\n") {
		t.Fatalf("signer editor text = %q, want the signer template", policyEditText(m))
	}
	if rendered := stripANSI(m.renderPolicyEdit()); !strings.Contains(rendered, "policy.json") || !strings.Contains(rendered, "Starting policy") || !strings.Contains(rendered, "// Lines starting with //") {
		t.Fatalf("signer editor:\n%s", rendered)
	}
	m = setPolicyEditText(m, `{"format":"aplane.signer-policy.v1","max_fee_microalgos":"2000"}`)
	m, cmd = pressPolicyKey(t, m, "ctrl+s")
	if cmd == nil || m.policies.apply.doc.Key != "" || m.policies.apply.file != "policy.json" {
		t.Fatalf("ctrl+s: apply %+v cmd %v", m.policies.apply, cmd)
	}
}

// A signer document that is not the starting document opens on its stored
// bytes, not the template.
func TestPolicyEditOpensNonStartingDocumentAsStored(t *testing.T) {
	m := loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer",
		Documents: []protocol.PolicyDocumentInfoWire{{SHA256: "abc", Size: 60}}, PolicySetSHA256: "set-digest"})
	m.width, m.height = 120, 40
	stored := "{\n  \"format\": \"aplane.signer-policy.v1\",\n  \"max_fee_microalgos\": \"2000\"\n}\n"
	m = openLoadedDocument(t, m, protocol.PolicyDocumentMessage{Success: true, Document: stored})
	m, _ = pressPolicyKey(t, m, "e")
	if edit := m.policies.apply.edit; edit.annotated || policyEditText(m) != strings.TrimRight(stored, "\n") {
		t.Fatalf("editor text = %q annotated %v, want the stored bytes", policyEditText(m), edit.annotated)
	}
}

// Comments in the editor are removed before the document reaches the node,
// and a syntax error is still located in the text as shown.
func TestPolicyEditStripsCommentsAndLocatesErrorsAroundThem(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, _ = pressPolicyKey(t, m, "e")
	commented := "{\n  // which document\n  \"format\": \"aplane.cosigner-policy.v1\",\n  \"key\": \"" + policyViewKeyA + "\", /* the key */\n  \"transfer_policy\": {\"routes\": []} // none yet\n}"
	m = setPolicyEditText(m, commented)
	m, cmd := pressPolicyKey(t, m, "ctrl+s")
	apply := m.policies.apply
	if cmd == nil || apply.err != "" || apply.doc.Key != policyViewKeyA {
		t.Fatalf("ctrl+s: apply %+v cmd %v", apply, cmd)
	}
	want := "{\n  \"format\": \"aplane.cosigner-policy.v1\",\n  \"key\": \"" + policyViewKeyA + "\",\n  \"transfer_policy\": {\"routes\": []}\n}\n"
	if apply.doc.Document != want {
		t.Fatalf("submitted document = %q, want %q", apply.doc.Document, want)
	}

	// A missing comma after line 4 is reported on line 5, past the comments.
	m.policies.apply.busy, m.policies.apply.pendingCheckID = "", ""
	m = setPolicyEditText(m, "{\n  // which document\n  \"format\": \"aplane.cosigner-policy.v1\",\n  \"key\": \""+policyViewKeyA+"\" /* the key */\n  \"transfer_policy\": {\"routes\": []}\n}")
	m, cmd = pressPolicyKey(t, m, "ctrl+s")
	if cmd != nil || !strings.Contains(m.policies.apply.err, "line 5, column 3") {
		t.Fatalf("syntax error = %q cmd %v, want line 5, column 3", m.policies.apply.err, cmd)
	}

	m = setPolicyEditText(m, "{\"format\": \"aplane.cosigner-policy.v1\" /* open")
	m, cmd = pressPolicyKey(t, m, "ctrl+s")
	if cmd != nil || !strings.Contains(m.policies.apply.err, "unterminated") {
		t.Fatalf("unterminated comment error = %q cmd %v", m.policies.apply.err, cmd)
	}
}

func TestPolicyEditFailedApplyReturnsToEditorAndReloadsSummary(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, _ = pressPolicyKey(t, m, "e")
	m, _ = pressPolicyKey(t, m, "ctrl+s")
	m = deliverPolicyCheck(m, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	text := policyEditText(m)
	m, _ = pressPolicyKey(t, m, "y")
	next, _ := m.handlePolicyApplyResult(PolicyApplyResultMsg{Result: protocol.ApplyPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.apply.pendingApplyID},
		Code:        "policy_snapshot_changed", Error: "active policy changed",
	}})
	m = next.(Model)
	rendered := stripANSI(m.renderPolicyApplyReview())
	if m.viewState != ViewPolicyApplyReview || !strings.Contains(rendered, "go back to the editor and check again") {
		t.Fatalf("failed apply: view %v\n%s", m.viewState, rendered)
	}
	m, cmd := pressPolicyKey(t, m, "esc")
	if m.viewState != ViewPolicyEdit || policyEditText(m) != text || m.policies.apply.applyErr != "" {
		t.Fatalf("esc after failure: view %v text %q apply %+v", m.viewState, policyEditText(m), m.policies.apply)
	}
	if cmd == nil || m.policies.pendingPolicyID == "" {
		t.Fatal("leaving a failed apply did not reload the policy summary")
	}
}

func TestPolicyEditStopsWaitingWithoutLosingText(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, _ = pressPolicyKey(t, m, "e")
	text := policyEditText(m)
	m, _ = pressPolicyKey(t, m, "ctrl+s")
	staleID := m.policies.apply.pendingCheckID

	// Typing is ignored while the check is pending.
	typed, _ := pressPolicyKey(t, m, "x")
	if policyEditText(typed) != text {
		t.Fatal("typing while the check was pending changed the text")
	}
	if footer := m.policyEditFooterText(); footer != "esc: Stop waiting" {
		t.Fatalf("busy footer = %q", footer)
	}
	m, _ = pressPolicyKey(t, m, "esc")
	if m.viewState != ViewPolicyEdit || m.policies.apply.busy != "" || policyEditText(m) != text {
		t.Fatalf("esc while busy: view %v busy %q text %q", m.viewState, m.policies.apply.busy, policyEditText(m))
	}
	// The abandoned check's answer no longer opens the review.
	next, _ := m.handlePolicyCheckResult(PolicyCheckResultMsg{Result: protocol.CheckPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{ID: staleID}, Success: true, Valid: true,
	}})
	if next.(Model).viewState != ViewPolicyEdit {
		t.Fatal("a stale check result opened the review")
	}
}

func TestPolicyEditRequestFailuresReachTheEditor(t *testing.T) {
	// The check could not be sent: the editor stays open and says why.
	m := cosignerPoliciesModel("no_policy")
	m, _ = pressPolicyKey(t, m, "e")
	m, _ = pressPolicyKey(t, m, "ctrl+s")
	m, handled := m.failPendingPolicyApply(m.policies.apply.pendingCheckID, errors.New("not connected"))
	if !handled || m.viewState != ViewPolicyEdit || m.policies.apply.busy != "" || m.policies.apply.err != "not connected" {
		t.Fatalf("failed check: handled %v view %v apply %+v", handled, m.viewState, m.policies.apply)
	}

	// The document could not be loaded: there is nothing to edit.
	m = cosignerPoliciesModel("active", protocol.PolicyDocumentInfoWire{Key: policyViewKeyA, SHA256: "abc", Size: 10})
	m, _ = pressPolicyKey(t, m, "e")
	m, handled = m.failPendingPolicyApply(m.policies.apply.edit.pendingDocumentID, errors.New("not connected"))
	if !handled || m.viewState != ViewPolicies || !strings.Contains(m.policies.status, "Could not open the policy for editing: not connected") {
		t.Fatalf("failed load: handled %v view %v status %q", handled, m.viewState, m.policies.status)
	}
}

func TestPolicyEditBoundsProblemLinesButShowsTheFirstInFull(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 60, 40
	m, _ = pressPolicyKey(t, m, "e")
	long := "error: key.json /transfer_policy/routes/0/destinations/0: " + strings.Repeat("explanation ", 12) + "END"
	for range 12 {
		m.policies.apply.problems = append(m.policies.apply.problems, long)
	}
	messages := m.policyEditMessages()
	var text []string
	for _, line := range messages {
		text = append(text, line.text)
	}
	joined := strings.Join(text, "\n")
	if !strings.Contains(joined, "END") {
		t.Fatalf("the first problem was cut short:\n%s", joined)
	}
	if !strings.Contains(joined, "… and 10 more") {
		t.Fatalf("remaining problems are not counted:\n%s", joined)
	}
	// The editor keeps a usable height however many problems there are.
	if height := m.sizedPolicyEditor().Height(); height < 5 {
		t.Fatalf("editor height = %d with %d message lines", height, len(messages))
	}
}

func TestEditablePolicyTextIndentsOnlySingleLineDocuments(t *testing.T) {
	if got := editablePolicyText(`{"format":"aplane.signer-policy.v1","max_fee_microalgos":"2000"}` + "\n"); got != "{\n  \"format\": \"aplane.signer-policy.v1\",\n  \"max_fee_microalgos\": \"2000\"\n}" {
		t.Fatalf("single-line document = %q", got)
	}
	laidOut := "{\n\t\"format\": \"aplane.signer-policy.v1\"\n}\n"
	if got := editablePolicyText(laidOut); got != strings.TrimRight(laidOut, "\n") {
		t.Fatalf("multi-line document was reformatted: %q", got)
	}
	if got := editablePolicyText("not json"); got != "not json" {
		t.Fatalf("unparseable document = %q", got)
	}
}

func TestPolicyJSONSyntaxErrorNamesLineAndColumn(t *testing.T) {
	if got := policyJSONSyntaxError(`{"a": 1}`); got != "" {
		t.Fatalf("valid JSON reported %q", got)
	}
	got := policyJSONSyntaxError("{\n  \"a\": 1,\n  \"b\": }\n")
	if !strings.HasPrefix(got, "Invalid JSON at line 3, column 8:") {
		t.Fatalf("syntax error = %q", got)
	}
	if got := policyJSONSyntaxError("{\n"); !strings.HasPrefix(got, "Invalid JSON at line 2, column 1:") {
		t.Fatalf("truncated document = %q", got)
	}
}

// After a failed apply the summary reloads in the background. Nothing may be
// checked against the stale summary meanwhile, and an apply always names the
// policy set its review was built from.
func TestPolicyEditCannotApplyAgainstAPolicySetItDidNotReview(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, _ = pressPolicyKey(t, m, "e")
	m, _ = pressPolicyKey(t, m, "ctrl+s")
	m = deliverPolicyCheck(m, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	if m.policies.apply.reviewedSetSHA256 != "set-digest" {
		t.Fatalf("review base = %q, want the summary the review was built from", m.policies.apply.reviewedSetSHA256)
	}
	m, _ = pressPolicyKey(t, m, "y")
	next, _ := m.handlePolicyApplyResult(PolicyApplyResultMsg{Result: protocol.ApplyPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.apply.pendingApplyID},
		Code:        "policy_snapshot_changed", Error: "active policy changed",
	}})
	m, _ = pressPolicyKey(t, next.(Model), "esc")
	if m.viewState != ViewPolicyEdit || !m.policies.loading {
		t.Fatalf("after a failed apply: view %v loading %v, want the editor with the summary reloading", m.viewState, m.policies.loading)
	}

	// While the summary reloads, a check is refused rather than built on it.
	blocked, cmd := pressPolicyKey(t, m, "ctrl+s")
	if cmd != nil || blocked.policies.apply.pendingCheckID != "" || !strings.Contains(blocked.policies.apply.err, "summary is reloading") {
		t.Fatalf("ctrl+s during reload: cmd %v apply %+v, want it refused", cmd, blocked.policies.apply)
	}

	// The reload shows that another operator gave the key a policy meanwhile.
	activeDoc := policyApplyCosignerDoc(policyViewKeyA, `"reject_clawback":true,`)
	next, _ = m.handlePolicyLoaded(PolicyLoadedMsg{Policy: protocol.PolicyMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.pendingPolicyID}, Success: true, NodeRole: "cosigner",
		Documents:       []protocol.PolicyDocumentInfoWire{{Key: policyViewKeyA, SHA256: "other", Size: 99}},
		Keys:            []protocol.PolicyKeyStatusWire{{Key: policyViewKeyA, Status: "active"}},
		PolicySetSHA256: "newer-digest",
	}})
	m = next.(Model)
	m, _ = pressPolicyKey(t, m, "ctrl+s")
	m = deliverPolicyCheck(m, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	if m.viewState != ViewPolicyEdit || m.policies.apply.pendingDocumentID == "" {
		t.Fatalf("check after reload: view %v apply %+v, want the existing document fetched for the diff", m.viewState, m.policies.apply)
	}
	next, _ = m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.apply.pendingDocumentID}, Success: true, Key: policyViewKeyA, Document: activeDoc,
	}})
	m = next.(Model)
	rendered := stripANSI(m.renderPolicyApplyReview())
	if m.viewState != ViewPolicyApplyReview || strings.Contains(rendered, "new policy") || !strings.Contains(rendered, "/reject_clawback") {
		t.Fatalf("review after reload must diff against the existing document:\n%s", rendered)
	}
	if m.policies.apply.reviewedSetSHA256 != "newer-digest" {
		t.Fatalf("review base = %q, want the reloaded policy set", m.policies.apply.reviewedSetSHA256)
	}

	// A summary that changes while the review is open does not move the base:
	// the apply still names the set that was reviewed, so the node rejects it.
	next, _ = m.requestPolicy()
	m = next.(Model)
	next, _ = m.handlePolicyLoaded(PolicyLoadedMsg{Policy: protocol.PolicyMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.pendingPolicyID}, Success: true, NodeRole: "cosigner",
		Keys: []protocol.PolicyKeyStatusWire{{Key: policyViewKeyA, Status: "active"}}, PolicySetSHA256: "newest-digest",
	}})
	m, cmd = pressPolicyKey(t, next.(Model), "y")
	if !m.policies.apply.applying || cmd == nil || m.policies.apply.reviewedSetSHA256 != "newer-digest" || m.policies.policy.PolicySetSHA256 != "newest-digest" {
		t.Fatalf("y: apply %+v summary set %q, want the apply bound to the reviewed set", m.policies.apply, m.policies.policy.PolicySetSHA256)
	}
}

// The text area drops lines past its capacity without notice. A document that
// does not fit is not opened, so a shortened copy can never pass as unmodified.
func TestPolicyEditRefusesDocumentItCannotHoldCompletely(t *testing.T) {
	oversized := `{"format":"aplane.signer-policy.v1",` + strings.Repeat("\n", policyEditMaxLines+10) + `"max_fee_microalgos":"2000"}`
	m := loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer",
		Documents: []protocol.PolicyDocumentInfoWire{{SHA256: "abc", Size: len(oversized)}}, PolicySetSHA256: "set-digest"})
	m, _ = pressPolicyKey(t, m, "e")
	next, _ := m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.apply.edit.pendingDocumentID}, Success: true, Document: oversized,
	}})
	m = next.(Model)
	if m.viewState != ViewPolicies || m.policies.apply.edit.active || !strings.Contains(m.policies.status, "too large to edit here") {
		t.Fatalf("oversized document: view %v status %q, want it refused on the list", m.viewState, m.policies.status)
	}

	// Whitespace the text area normalizes is not a loss: tabs become spaces.
	tabbed := "{\n\t\"format\": \"aplane.signer-policy.v1\"\n}\n"
	opened := loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer", PolicySetSHA256: "set-digest"}).startPolicyEditor("", tabbed, false)
	if opened.viewState != ViewPolicyEdit || !strings.Contains(policyEditText(opened), `"format": "aplane.signer-policy.v1"`) {
		t.Fatalf("tab-indented document: view %v status %q, want it opened", opened.viewState, opened.policies.status)
	}
}

func TestPolicyEditReportsPasteCutOffAtTheLineLimit(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, _ = pressPolicyKey(t, m, "e")
	next, _ := m.handlePolicyEditKeys(tea.KeyMsg{Type: tea.KeyRunes, Paste: true, Runes: []rune(strings.Repeat("\n", policyEditMaxLines+50))})
	m = next.(Model)
	if m.policies.apply.edit.input.LineCount() > policyEditMaxLines || !strings.Contains(m.policies.apply.err, "was not inserted") {
		t.Fatalf("oversized paste: lines %d err %q, want the cut-off reported", m.policies.apply.edit.input.LineCount(), m.policies.apply.err)
	}
	if rendered := stripANSI(m.renderPolicyEdit()); !strings.Contains(rendered, "its end was not inserted") {
		t.Fatalf("editor does not show the cut-off:\n%s", rendered)
	}

	// A paste that fits reports nothing.
	small := cosignerPoliciesModel("no_policy")
	small.width, small.height = 120, 40
	small, _ = pressPolicyKey(t, small, "e")
	next, _ = small.handlePolicyEditKeys(tea.KeyMsg{Type: tea.KeyRunes, Paste: true, Runes: []rune("\n\n\n")})
	if got := next.(Model); got.policies.apply.err != "" {
		t.Fatalf("small paste reported %q", got.policies.apply.err)
	}
}

// Paste comes from the terminal as key input. The component's ctrl+v binding,
// which would read this machine's clipboard through a helper program and
// return an answer the view never receives, is off.
func TestPolicyEditTakesTerminalPasteAndIgnoresClipboardBinding(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	m.width, m.height = 120, 40
	m, _ = pressPolicyKey(t, m, "e")
	before := policyEditText(m)

	next, cmd := m.handlePolicyEditKeys(tea.KeyMsg{Type: tea.KeyCtrlV})
	if cmd != nil || policyEditText(next.(Model)) != before {
		t.Fatalf("ctrl+v: cmd %v text changed %v, want the clipboard binding inert", cmd, policyEditText(next.(Model)) != before)
	}

	pasted := "// first\n// second\n"
	next, _ = m.handlePolicyEditKeys(tea.KeyMsg{Type: tea.KeyRunes, Paste: true, Runes: []rune(pasted)})
	if got := policyEditText(next.(Model)); !strings.HasPrefix(got, pasted+"{") || next.(Model).policies.apply.err != "" {
		t.Fatalf("terminal paste: text %q err %q, want the pasted lines inserted", got, next.(Model).policies.apply.err)
	}
}
