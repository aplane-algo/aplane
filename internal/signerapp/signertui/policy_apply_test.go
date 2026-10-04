// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

func policyApplyCosignerDoc(key, extra string) string {
	return fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,%s"transfer_policy":{"routes":[]}}`, key, extra)
}

func writePolicyApplyFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// submitPolicyApplyPath opens the load form from the policies list, types
// path, and presses enter.
func submitPolicyApplyPath(t *testing.T, m Model, path string) (Model, tea.Cmd) {
	t.Helper()
	next, _ := m.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m = next.(Model)
	if m.viewState != ViewPolicyApplyForm {
		t.Fatalf("a: view %v, want ViewPolicyApplyForm", m.viewState)
	}
	next, _ = m.handlePolicyApplyFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(path)})
	next, cmd := next.(Model).handlePolicyApplyFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	return next.(Model), cmd
}

func deliverPolicyCheck(m Model, result protocol.CheckPolicyResultMessage) Model {
	result.ID = m.policies.apply.pendingCheckID
	next, _ := m.handlePolicyCheckResult(PolicyCheckResultMsg{Result: result})
	return next.(Model)
}

func cosignerPoliciesModel(status string, documents ...protocol.PolicyDocumentInfoWire) Model {
	return loadedPoliciesModel(protocol.PolicyMessage{
		Success:         true,
		NodeRole:        "cosigner",
		Documents:       documents,
		Keys:            []protocol.PolicyKeyStatusWire{{Key: policyViewKeyA, Status: status}},
		PolicySetSHA256: "set-digest",
	})
}

func TestPolicyApplyLoadsFileForKeyWithoutPolicy(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	path := writePolicyApplyFile(t, "key-a.json", policyApplyCosignerDoc(policyViewKeyA, ""))
	m, cmd := submitPolicyApplyPath(t, m, path)
	if m.policies.apply.pendingCheckID == "" || m.policies.apply.busy == "" || cmd == nil {
		t.Fatalf("enter: apply state %+v cmd %v", m.policies.apply, cmd)
	}
	// Keys other than esc are ignored while the check is pending.
	next, _ := m.handlePolicyApplyFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if next.(Model).policies.apply.path != path {
		t.Fatal("typing while busy changed the path")
	}

	m = deliverPolicyCheck(m, protocol.CheckPolicyResultMessage{Success: true, Valid: true,
		Warnings: []protocol.PolicyProblemWire{{Key: policyViewKeyB, Message: "key is held but has no policy; it will reject every request"}}})
	if m.viewState != ViewPolicyApplyReview || m.policies.apply.pendingDocumentID != "" {
		t.Fatalf("check: view %v apply %+v", m.viewState, m.policies.apply)
	}
	rendered := stripANSI(m.renderPolicyApplyReview())
	for _, want := range []string{"key-a.json", "cosigner key " + policyViewKeyA, "warning: " + policyViewKeyB, "loosened", "new policy", "Apply these changes?"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("review missing %q:\n%s", want, rendered)
		}
	}
	if footer := m.policyApplyFooterText(); !strings.Contains(footer, "y: Apply") {
		t.Fatalf("review footer = %q", footer)
	}

	// Enter does not confirm; only y applies.
	next, cmd = m.handlePolicyApplyReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if next.(Model).policies.apply.applying || cmd != nil {
		t.Fatal("enter applied the policy")
	}
	next, cmd = m.handlePolicyApplyReviewKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m = next.(Model)
	if !m.policies.apply.applying || m.policies.apply.pendingApplyID == "" || cmd == nil {
		t.Fatalf("y: apply state %+v cmd %v", m.policies.apply, cmd)
	}

	next, cmd = m.handlePolicyApplyResult(PolicyApplyResultMsg{Result: protocol.ApplyPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.apply.pendingApplyID},
		Success:     true,
		Policy:      &protocol.PolicyMessage{Success: true, GenerationID: "gen-7"},
	}})
	m = next.(Model)
	if m.viewState != ViewPolicies || !m.policies.loading || cmd == nil || m.policies.apply.path != "" {
		t.Fatalf("applied: view %v loading %v apply %+v", m.viewState, m.policies.loading, m.policies.apply)
	}
	if m.policies.status != "Applied key-a.json as generation gen-7" {
		t.Fatalf("status = %q", m.policies.status)
	}
}

func TestPolicyApplyRejectsKeyTheNodeDoesNotHold(t *testing.T) {
	path := writePolicyApplyFile(t, "key-a.json", policyApplyCosignerDoc(policyViewKeyA, ""))
	for name, m := range map[string]Model{
		"unknown key":  loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "cosigner", Keys: []protocol.PolicyKeyStatusWire{{Key: policyViewKeyB, Status: "no_policy"}}}),
		"key not held": cosignerPoliciesModel("key_not_held", protocol.PolicyDocumentInfoWire{Key: policyViewKeyA, SHA256: "abc"}),
	} {
		got, cmd := submitPolicyApplyPath(t, m, path)
		if got.viewState != ViewPolicyApplyForm || cmd != nil || got.policies.apply.pendingCheckID != "" {
			t.Fatalf("%s: view %v cmd %v apply %+v", name, got.viewState, cmd, got.policies.apply)
		}
		if !strings.Contains(got.policies.apply.err, "does not hold cosigner key "+policyViewKeyA) {
			t.Fatalf("%s: error = %q", name, got.policies.apply.err)
		}
		if !strings.Contains(stripANSI(got.renderPolicyApplyForm()), "does not hold cosigner key") {
			t.Fatalf("%s: form does not show the error:\n%s", name, got.renderPolicyApplyForm())
		}
	}
}

func TestPolicyApplyFormReportsFileAndCheckErrors(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	for path, want := range map[string]string{
		"":  "required",
		"-": "requires a file path",
		filepath.Join(t.TempDir(), "missing.json"):                                      "no such file",
		writePolicyApplyFile(t, "nokey.json", `{"format":"aplane.cosigner-policy.v1"}`): `"key" field`,
	} {
		got, cmd := submitPolicyApplyPath(t, m, path)
		if cmd != nil || !strings.Contains(got.policies.apply.err, want) {
			t.Fatalf("path %q: cmd %v error %q, want %q", path, cmd, got.policies.apply.err, want)
		}
	}

	path := writePolicyApplyFile(t, "key-a.json", policyApplyCosignerDoc(policyViewKeyA, ""))
	checking, _ := submitPolicyApplyPath(t, m, path)
	invalid := deliverPolicyCheck(checking, protocol.CheckPolicyResultMessage{Success: true,
		Errors: []protocol.PolicyProblemWire{{Key: policyViewKeyA, Pointer: "/transfer_policy", Message: "is required"}}})
	rendered := stripANSI(invalid.renderPolicyApplyForm())
	if invalid.viewState != ViewPolicyApplyForm || !strings.Contains(rendered, "Policy is invalid") ||
		!strings.Contains(rendered, "error: key-a.json /transfer_policy: is required") {
		t.Fatalf("invalid check: view %v\n%s", invalid.viewState, rendered)
	}
	// Editing the path clears the stale problems.
	next, _ := invalid.handlePolicyApplyFormKeys(tea.KeyMsg{Type: tea.KeyBackspace})
	if got := next.(Model).policies.apply; got.err != "" || got.problems != nil {
		t.Fatalf("after edit: %+v", got)
	}

	failed := deliverPolicyCheck(checking, protocol.CheckPolicyResultMessage{Code: "policy_unavailable", Error: "policy is not loaded"})
	if failed.policies.apply.err != "policy is not loaded (policy_unavailable)" {
		t.Fatalf("failed check error = %q", failed.policies.apply.err)
	}

	// A response to an abandoned request is ignored.
	stale, _ := checking.handlePolicyCheckResult(PolicyCheckResultMsg{Result: protocol.CheckPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{ID: "other"}, Success: true, Valid: true}})
	if stale.(Model).viewState != ViewPolicyApplyForm || stale.(Model).policies.apply.pendingCheckID == "" {
		t.Fatal("stale check result advanced the workflow")
	}
	cancelled, _ := checking.handlePolicyApplyFormKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if got := cancelled.(Model); got.viewState != ViewPolicies || got.policies.apply.pendingCheckID != "" {
		t.Fatalf("esc: view %v apply %+v", got.viewState, got.policies.apply)
	}
}

func TestPolicyApplyDiffsAgainstActiveDocument(t *testing.T) {
	active := policyApplyCosignerDoc(policyViewKeyA, "")
	m := cosignerPoliciesModel("active", protocol.PolicyDocumentInfoWire{Key: policyViewKeyA, SHA256: "abc", Size: len(active)})
	deliverActive := func(m Model, doc protocol.PolicyDocumentMessage) Model {
		t.Helper()
		if m.viewState != ViewPolicyApplyForm || m.policies.apply.pendingDocumentID == "" {
			t.Fatalf("check did not request the active document: view %v apply %+v", m.viewState, m.policies.apply)
		}
		doc.ID = m.policies.apply.pendingDocumentID
		next, _ := m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: doc})
		return next.(Model)
	}

	changedPath := writePolicyApplyFile(t, "changed.json", policyApplyCosignerDoc(policyViewKeyA, `"reject_rekey":true,`))
	changed, _ := submitPolicyApplyPath(t, m, changedPath)
	changed = deliverPolicyCheck(changed, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	changed = deliverActive(changed, protocol.PolicyDocumentMessage{Success: true, Key: policyViewKeyA, Document: active})
	rendered := stripANSI(changed.renderPolicyApplyReview())
	if changed.viewState != ViewPolicyApplyReview || changed.policies.apply.unchanged ||
		!strings.Contains(rendered, "tightened") || !strings.Contains(rendered, "/reject_rekey") {
		t.Fatalf("changed review: view %v\n%s", changed.viewState, rendered)
	}

	// Reformatting the active document changes nothing, so y does not apply.
	samePath := writePolicyApplyFile(t, "same.json", "  "+active+"\n")
	same, _ := submitPolicyApplyPath(t, m, samePath)
	same = deliverPolicyCheck(same, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	same = deliverActive(same, protocol.PolicyDocumentMessage{Success: true, Key: policyViewKeyA, Document: active})
	if !same.policies.apply.unchanged || !strings.Contains(stripANSI(same.renderPolicyApplyReview()), "Policy unchanged") {
		t.Fatalf("identical review:\n%s", same.renderPolicyApplyReview())
	}
	next, cmd := same.handlePolicyApplyReviewKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if next.(Model).policies.apply.applying || cmd != nil {
		t.Fatal("y applied an unchanged policy")
	}
	if footer := same.policyApplyFooterText(); strings.Contains(footer, "Apply") {
		t.Fatalf("unchanged footer = %q", footer)
	}

	unavailable, _ := submitPolicyApplyPath(t, m, changedPath)
	unavailable = deliverPolicyCheck(unavailable, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	unavailable = deliverActive(unavailable, protocol.PolicyDocumentMessage{Code: "policy_unavailable", Error: "policy is not loaded"})
	if unavailable.viewState != ViewPolicyApplyForm || !strings.Contains(unavailable.policies.apply.err, "policy is not loaded") {
		t.Fatalf("unavailable active document: view %v err %q", unavailable.viewState, unavailable.policies.apply.err)
	}
}

func TestPolicyApplySignerFileAndApplyFailure(t *testing.T) {
	m := loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer",
		Documents: []protocol.PolicyDocumentInfoWire{{SHA256: "abc", Size: 34}}, PolicySetSHA256: "set-digest"})
	path := writePolicyApplyFile(t, "policy.json", `{"format":"aplane.signer-policy.v1","max_fee_microalgos":"2000"}`)
	m, _ = submitPolicyApplyPath(t, m, path)
	m = deliverPolicyCheck(m, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	next, _ := m.handlePolicyDocumentLoaded(PolicyDocumentLoadedMsg{Document: protocol.PolicyDocumentMessage{
		BaseMessage: protocol.BaseMessage{ID: m.policies.apply.pendingDocumentID},
		Success:     true, Document: `{"format":"aplane.signer-policy.v1"}`}})
	m = next.(Model)
	rendered := stripANSI(m.renderPolicyApplyReview())
	if m.viewState != ViewPolicyApplyReview || !strings.Contains(rendered, "/max_fee_microalgos") || !strings.Contains(rendered, "policy.json  →  policy.json") {
		t.Fatalf("signer review: view %v\n%s", m.viewState, rendered)
	}

	next, _ = m.handlePolicyApplyReviewKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	applying := next.(Model)
	next, _ = applying.handlePolicyApplyResult(PolicyApplyResultMsg{Result: protocol.ApplyPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{ID: applying.policies.apply.pendingApplyID},
		Code:        "policy_snapshot_changed", Error: "active policy changed",
	}})
	m = next.(Model)
	rendered = stripANSI(m.renderPolicyApplyReview())
	if m.viewState != ViewPolicyApplyReview || m.policies.apply.applying ||
		!strings.Contains(rendered, "Apply failed: active policy changed (policy_snapshot_changed)") {
		t.Fatalf("failed apply: view %v\n%s", m.viewState, rendered)
	}
	// A failed review cannot be applied again; leaving it refreshes the list.
	next, cmd := m.handlePolicyApplyReviewKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if next.(Model).policies.apply.applying || cmd != nil {
		t.Fatal("y retried a failed apply")
	}
	next, cmd = m.handlePolicyApplyReviewKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if got := next.(Model); got.viewState != ViewPolicies || !got.policies.loading || cmd == nil {
		t.Fatalf("esc after failure: view %v loading %v cmd %v", got.viewState, got.policies.loading, cmd)
	}

	// An uncertain commit has put the daemon into recovery without a status
	// message, so the TUI opens the recovery screen itself.
	next, cmd = applying.handlePolicyApplyResult(PolicyApplyResultMsg{Result: protocol.ApplyPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{ID: applying.policies.apply.pendingApplyID},
		Code:        "policy_reload_failed", Error: "policy committed as generation gen-9 but runtime reload failed", CommitUncertain: true,
	}})
	uncertain := next.(Model)
	if uncertain.viewState != ViewStoreRecovery || uncertain.signerState != signerRuntimeRecovery || cmd == nil ||
		uncertain.policies.apply.pendingApplyID != "" {
		t.Fatalf("uncertain commit: view %v state %v cmd %v apply %+v", uncertain.viewState, uncertain.signerState, cmd, uncertain.policies.apply)
	}
	if want := "Policy apply: policy committed as generation gen-9 but runtime reload failed (policy_reload_failed)"; uncertain.restore.recoveryError != want {
		t.Fatalf("recovery error = %q, want %q", uncertain.restore.recoveryError, want)
	}
	if rendered := stripANSI(uncertain.renderStoreRecovery()); !strings.Contains(rendered, "Signing is disabled") ||
		!strings.Contains(rendered, "Policy apply: policy committed as generation gen-9") {
		t.Fatalf("recovery screen after an uncertain commit:\n%s", rendered)
	}
}

func TestPolicyApplyUntypedFailureReleasesOnlyItsOwnRequest(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	path := writePolicyApplyFile(t, "key-a.json", policyApplyCosignerDoc(policyViewKeyA, ""))
	checking, _ := submitPolicyApplyPath(t, m, path)

	// An error for another request, such as a background key-list refresh,
	// leaves the check pending, and its real response still arrives.
	for _, unrelated := range []ErrorMsg{{Error: fmt.Errorf("list failed")}, {ID: "list-keys-1", Error: fmt.Errorf("list failed")}} {
		next, _ := checking.Update(unrelated)
		got := next.(Model)
		if got.viewState != ViewPolicyApplyForm || got.policies.apply.busy == "" || got.policies.apply.pendingCheckID != checking.policies.apply.pendingCheckID {
			t.Fatalf("unrelated error %+v released the check: view %v apply %+v", unrelated, got.viewState, got.policies.apply)
		}
		if reviewed := deliverPolicyCheck(got, protocol.CheckPolicyResultMessage{Success: true, Valid: true}); reviewed.viewState != ViewPolicyApplyReview {
			t.Fatalf("check result after an unrelated error: view %v", reviewed.viewState)
		}
	}

	next, _ := checking.Update(ErrorMsg{ID: checking.policies.apply.pendingCheckID, Error: fmt.Errorf("authorization denied")})
	if got := next.(Model); got.viewState != ViewPolicyApplyForm || got.policies.apply.busy != "" || got.policies.apply.err != "authorization denied" {
		t.Fatalf("denied check: view %v apply %+v", got.viewState, got.policies.apply)
	}

	review := deliverPolicyCheck(checking, protocol.CheckPolicyResultMessage{Success: true, Valid: true})
	next, _ = review.handlePolicyApplyReviewKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	applying := next.(Model)

	next, _ = applying.Update(ErrorMsg{ID: "list-keys-2", Error: fmt.Errorf("list failed")})
	if got := next.(Model); !got.policies.apply.applying || got.policies.apply.pendingApplyID != applying.policies.apply.pendingApplyID || got.policies.apply.applyErr != "" {
		t.Fatalf("unrelated error released the apply: %+v", got.policies.apply)
	}

	next, _ = applying.Update(ErrorMsg{ID: applying.policies.apply.pendingApplyID, Error: fmt.Errorf("authorization denied")})
	got := next.(Model)
	if got.viewState != ViewPolicyApplyReview || got.policies.apply.applying || got.policies.apply.applyErr != "Apply failed: authorization denied" {
		t.Fatalf("denied apply: view %v apply %+v", got.viewState, got.policies.apply)
	}
	if footer := got.policyApplyFooterText(); !strings.Contains(footer, "esc: Back") || strings.Contains(footer, "Apply") {
		t.Fatalf("denied apply footer = %q", footer)
	}

	// A request that could not be sent fails the step waiting on it.
	failed, ok := policyRequestCmd(nil, applying.policies.apply.pendingApplyID, func(*IPCClient) error { return nil })().(policyRequestFailedMsg)
	if !ok {
		t.Fatal("unsent policy request did not report a policy request failure")
	}
	next, cmd := applying.Update(failed)
	if got := next.(Model); got.policies.apply.applying || got.policies.apply.applyErr != "Apply failed: not connected" || cmd != nil {
		t.Fatalf("unsent apply: apply %+v cmd %v", got.policies.apply, cmd)
	}
}

func TestPolicyApplyRejectsPathsThatAreNotRegularFiles(t *testing.T) {
	m := cosignerPoliciesModel("no_policy")
	dir := t.TempDir()
	fifo := filepath.Join(dir, "policy.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(writePolicyApplyFile(t, "key-a.json", policyApplyCosignerDoc(policyViewKeyA, "")), link); err != nil {
		t.Fatal(err)
	}
	// Opening a FIFO with no writer would block the event loop forever; the
	// submit must return an error instead.
	for _, path := range []string{fifo, link, dir} {
		got, cmd := submitPolicyApplyPath(t, m, path)
		if cmd != nil || got.policies.apply.err == "" || got.policies.apply.pendingCheckID != "" {
			t.Fatalf("path %s: cmd %v apply %+v", path, cmd, got.policies.apply)
		}
	}
}

func TestPolicyApplyIsUnavailableUntilPolicyLoads(t *testing.T) {
	failed := loadedPoliciesModel(protocol.PolicyMessage{Code: "policy_unavailable", Error: "policy is not loaded"})
	next, _ := failed.handlePoliciesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if next.(Model).viewState != ViewPolicies {
		t.Fatalf("a on an unavailable policy opened %v", next.(Model).viewState)
	}
}

func TestWrapIndentedLineKeepsIndentation(t *testing.T) {
	line := "  loosened   /transfer_policy/routes/approved: " + strings.Repeat("destination ", 12)
	wrapped := wrapIndentedLine(line, 60)
	if len(wrapped) < 2 || !strings.HasPrefix(wrapped[0], "  loosened") || !strings.HasPrefix(wrapped[1], "    ") {
		t.Fatalf("wrapped = %q", wrapped)
	}
	for _, part := range wrapped {
		if len(part) > 60 {
			t.Fatalf("line exceeds width: %q", part)
		}
	}
	if got := wrapIndentedLine("short", 60); len(got) != 1 || got[0] != "short" {
		t.Fatalf("short line = %q", got)
	}
}
