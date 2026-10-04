// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyreview"
	tea "github.com/charmbracelet/bubbletea"
)

// The policies view can load one policy file through the same check, diff,
// confirm, and apply steps as apadmin policy apply. The TUI never edits a
// document: the file's exact bytes are what the node stores. Unlike the batch
// command, a cosigner file for a key the node does not hold is an error here.

// policyApplyState is the load-policy-file workflow.
type policyApplyState struct {
	path string
	// busy names the request the form is waiting for; keys other than esc are
	// ignored until it resolves.
	busy string
	err  string
	// problems are the check errors and warnings for a rejected file.
	problems []string

	doc       adminproto.PolicyDocument
	file      string
	warnings  []string
	diffLines []string
	unchanged bool

	applying     bool
	applyErr     string
	scrollOffset int

	// Responses to any request other than these are stale and ignored.
	pendingCheckID    string
	pendingDocumentID string
	pendingApplyID    string
}

// PolicyCheckResultMsg carries the daemon's check_policy response.
type PolicyCheckResultMsg struct {
	Result protocol.CheckPolicyResultMessage
}

// PolicyApplyResultMsg carries the daemon's apply_policy response.
type PolicyApplyResultMsg struct {
	Result protocol.ApplyPolicyResultMessage
}

func (m Model) openPolicyApply() (tea.Model, tea.Cmd) {
	if m.policies.loading || m.policies.err != "" || !m.policies.policy.Success {
		return m, nil
	}
	m.policies.apply = policyApplyState{}
	m.policies.status = ""
	m.viewState = ViewPolicyApplyForm
	return m, nil
}

func (m Model) closePolicyApply() Model {
	m.policies.apply = policyApplyState{}
	m.viewState = ViewPolicies
	return m
}

func (m Model) handlePolicyApplyFormKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		return m.closePolicyApply(), nil
	}
	if m.policies.apply.busy != "" {
		return m, nil
	}
	switch msg.String() {
	case "enter":
		return m.submitPolicyApplyFile()
	case "backspace", "delete":
		m.policies.apply.path = trimLastRune(m.policies.apply.path)
		m.policies.apply.err = ""
		m.policies.apply.problems = nil
		return m, nil
	}
	if msg.Type == tea.KeyRunes {
		m.policies.apply.path += string(msg.Runes)
		m.policies.apply.err = ""
		m.policies.apply.problems = nil
	}
	return m, nil
}

// submitPolicyApplyFile reads the file and asks the daemon to check it.
func (m Model) submitPolicyApplyFile() (tea.Model, tea.Cmd) {
	apply := &m.policies.apply
	apply.problems = nil
	path := strings.TrimSpace(apply.path)
	switch path {
	case "":
		apply.err = "Policy file is required"
		return m, nil
	case "-":
		apply.err = "The interactive TUI requires a file path; use batch apadmin policy apply - for stdin"
		return m, nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			apply.err = fmt.Sprintf("resolve home directory: %v", err)
			return m, nil
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	role := m.policies.policy.NodeRole
	// Regular files only: this runs inside the event loop, where opening a
	// FIFO or device would block every key, timer, and daemon message.
	docs, _, err := policyreview.ReadRegularDocuments([]string{path}, role)
	if err != nil {
		apply.err = err.Error()
		return m, nil
	}
	doc := docs[0]
	if role == "cosigner" && !m.policyKeyHeld(doc.Key) {
		apply.err = fmt.Sprintf("this node does not hold cosigner key %s; generate the key before loading its policy", doc.Key)
		return m, nil
	}
	apply.doc = doc
	apply.file = filepath.Base(path)
	apply.err = ""
	apply.busy = "Checking policy..."
	apply.pendingCheckID = newRequestID("policy-check")
	return m, tea.Batch(m.sendCheckPolicyCmd(doc, apply.pendingCheckID), m.waitForMessageCmd())
}

// policyKeyHeld reports whether the loaded policy summary lists key as a
// cosigner key the node holds.
func (m Model) policyKeyHeld(key string) bool {
	for _, st := range m.policies.policy.Keys {
		if st.Key == key {
			return st.Status != adminproto.PolicyKeyNotHeld
		}
	}
	return false
}

// policyHasActiveDocument reports whether the loaded policy summary lists an
// active document for key.
func (m Model) policyHasActiveDocument(key string) bool {
	for _, doc := range m.policies.policy.Documents {
		if doc.Key == key {
			return true
		}
	}
	return false
}

func policyProblemLines(label string, problems []protocol.PolicyProblemWire, names map[string]string) []string {
	converted := make([]adminproto.PolicyProblem, 0, len(problems))
	for _, problem := range problems {
		converted = append(converted, adminproto.PolicyProblem{Key: problem.Key, Pointer: problem.Pointer, Message: problem.Message})
	}
	var sb strings.Builder
	policyreview.PrintProblems(&sb, label, converted, names)
	return splitPolicyLines(sb.String())
}

func splitPolicyLines(text string) []string {
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func policyResultError(code, msg, fallback string) string {
	if msg == "" {
		msg = fallback
	}
	if code == "" {
		return msg
	}
	return fmt.Sprintf("%s (%s)", msg, code)
}

func (m Model) handlePolicyCheckResult(msg PolicyCheckResultMsg) (tea.Model, tea.Cmd) {
	apply := &m.policies.apply
	if msg.Result.ID == "" || msg.Result.ID != apply.pendingCheckID {
		return m, m.waitForMessageCmd()
	}
	apply.pendingCheckID = ""
	apply.busy = ""
	if !msg.Result.Success {
		apply.err = policyResultError(msg.Result.Code, msg.Result.Error, "policy check failed")
		return m, m.waitForMessageCmd()
	}
	names := map[string]string{apply.doc.Key: apply.file}
	warnings := policyProblemLines("warning", msg.Result.Warnings, names)
	if !msg.Result.Valid {
		apply.problems = append(policyProblemLines("error", msg.Result.Errors, names), warnings...)
		apply.err = "Policy is invalid"
		return m, m.waitForMessageCmd()
	}
	apply.warnings = warnings
	if !m.policyHasActiveDocument(apply.doc.Key) {
		return m.reviewPolicyApply(false, "")
	}
	apply.busy = "Loading active policy..."
	apply.pendingDocumentID = newRequestID("policy-apply-doc")
	key, id := apply.doc.Key, apply.pendingDocumentID
	return m, tea.Batch(
		policyRequestCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendGetPolicyDocument(key, id) }),
		m.waitForMessageCmd(),
	)
}

// handlePolicyApplyDocumentLoaded receives the active document the candidate
// is diffed against.
func (m Model) handlePolicyApplyDocumentLoaded(msg PolicyDocumentLoadedMsg) (tea.Model, tea.Cmd) {
	apply := &m.policies.apply
	apply.pendingDocumentID = ""
	apply.busy = ""
	if !msg.Document.Success && msg.Document.Code != "policy_document_not_found" {
		apply.err = policyResultError(msg.Document.Code, msg.Document.Error, "active policy is unavailable")
		return m, m.waitForMessageCmd()
	}
	return m.reviewPolicyApply(msg.Document.Success, msg.Document.Document)
}

// reviewPolicyApply diffs the checked candidate against the active document
// and opens the review.
func (m Model) reviewPolicyApply(hasCurrent bool, current string) (tea.Model, tea.Cmd) {
	apply := &m.policies.apply
	changes, identical, err := policyreview.DiffDocument(m.policies.policy.NodeRole, apply.doc.Key, hasCurrent, current, apply.doc.Document)
	if err != nil {
		apply.err = err.Error()
		return m, m.waitForMessageCmd()
	}
	var sb strings.Builder
	policyreview.PrintDiffs(&sb, []policyreview.DocumentDiff{{Label: apply.file, Changes: changes, Identical: identical}})
	apply.diffLines = splitPolicyLines(sb.String())
	apply.unchanged = identical
	apply.scrollOffset = 0
	apply.applyErr = ""
	m.viewState = ViewPolicyApplyReview
	return m, m.waitForMessageCmd()
}

func (m Model) handlePolicyApplyReviewKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	apply := &m.policies.apply
	if apply.applying {
		return m, nil
	}
	maxOffset := max(0, len(m.policyApplyReviewLines())-m.policyApplyVisibleLines())
	switch msg.String() {
	case "esc", "n", "q":
		failed := apply.applyErr != ""
		m = m.closePolicyApply()
		if failed {
			// A failed apply may mean the active policy moved; show it fresh.
			return m.requestPolicy()
		}
		return m, nil
	case "y":
		if apply.unchanged || apply.applyErr != "" {
			return m, nil
		}
		apply.applying = true
		apply.pendingApplyID = newRequestID("policy-apply")
		return m, tea.Batch(
			m.sendApplyPolicyCmd(apply.doc, m.policies.policy.PolicySetSHA256, apply.pendingApplyID),
			m.waitForMessageCmd(),
		)
	case "up", "k":
		apply.scrollOffset--
	case "down", "j":
		apply.scrollOffset++
	case "pgup":
		apply.scrollOffset -= m.policyApplyVisibleLines()
	case "pgdown":
		apply.scrollOffset += m.policyApplyVisibleLines()
	}
	apply.scrollOffset = max(0, min(apply.scrollOffset, maxOffset))
	return m, nil
}

func (m Model) handlePolicyApplyResult(msg PolicyApplyResultMsg) (tea.Model, tea.Cmd) {
	apply := &m.policies.apply
	if msg.Result.ID == "" || msg.Result.ID != apply.pendingApplyID {
		return m, m.waitForMessageCmd()
	}
	apply.pendingApplyID = ""
	apply.applying = false
	if !msg.Result.Success {
		detail := policyResultError(msg.Result.Code, msg.Result.Error, "policy apply failed")
		if msg.Result.CommitUncertain {
			// The daemon has entered recovery without announcing it: the
			// commit may be visible but signing is blocked. Open the recovery
			// screen, where reconcile and rollback live, instead of leaving
			// the operator on a view that believes the signer is unlocked.
			m.policies = policiesState{}
			m.applySignerRecoveryState()
			m.restore.recoveryError = "Policy apply: " + detail
			return m, tea.Batch(m.waitForMessageCmd(), m.sendGetAdminSettingsCmd(), m.armLocalIdleTimer())
		}
		lines := policyProblemLines("error", msg.Result.Errors, map[string]string{apply.doc.Key: apply.file})
		lines = append(lines, "Apply failed: "+detail)
		apply.applyErr = strings.Join(lines, "\n")
		apply.scrollOffset = 0
		return m, m.waitForMessageCmd()
	}
	status := "Policy unchanged"
	if msg.Result.Policy != nil && msg.Result.Policy.GenerationID != "" {
		status = fmt.Sprintf("Applied %s as generation %s", apply.file, msg.Result.Policy.GenerationID)
	}
	m = m.closePolicyApply()
	m.policies.status = status
	return m.requestPolicy()
}

// policyRequestFailedMsg reports that a policy request could not be sent.
type policyRequestFailedMsg struct {
	id  string
	err error
}

// policyRequestCmd sends one policy request and ties a send failure to its
// request ID, so the failure reaches the step that is waiting on it.
func policyRequestCmd(client *IPCClient, id string, send func(*IPCClient) error) tea.Cmd {
	return func() tea.Msg {
		if client == nil {
			return policyRequestFailedMsg{id: id, err: fmt.Errorf("not connected")}
		}
		if err := send(client); err != nil {
			return policyRequestFailedMsg{id: id, err: err}
		}
		return nil
	}
}

// failPendingPolicyApply routes an untyped failure (authorization denial, a
// send error) to the request the workflow is waiting on, so the operator is
// not left on a screen that ignores keys. id must name that request: an error
// for any other request, such as a background refresh, leaves the workflow
// waiting for its own response.
func (m Model) failPendingPolicyApply(id string, err error) (Model, bool) {
	apply := &m.policies.apply
	if id == "" || (id != apply.pendingCheckID && id != apply.pendingDocumentID && id != apply.pendingApplyID) {
		return m, false
	}
	switch {
	case m.viewState == ViewPolicyApplyForm && apply.busy != "":
		apply.busy = ""
		apply.pendingCheckID = ""
		apply.pendingDocumentID = ""
		apply.err = err.Error()
	case m.viewState == ViewPolicyApplyReview && apply.applying:
		apply.applying = false
		apply.pendingApplyID = ""
		apply.applyErr = "Apply failed: " + err.Error()
		apply.scrollOffset = 0
	default:
		return m, false
	}
	return m, true
}

func (m Model) policyApplyTargetLabel() string {
	if key := m.policies.apply.doc.Key; key != "" {
		return "cosigner key " + key
	}
	return "policy.json"
}

// policyApplyReviewLine is one wrapped line of the review body.
type policyApplyReviewLine struct {
	text      string
	attention bool
}

func (m Model) policyApplyReviewWidth() int {
	if m.width < 20 {
		return 80
	}
	return m.width
}

// policyApplyReviewLines is the scrollable review body: an apply failure if
// there is one, then the check warnings, then the diff.
func (m Model) policyApplyReviewLines() []policyApplyReviewLine {
	apply := m.policies.apply
	width := m.policyApplyReviewWidth()
	var out []policyApplyReviewLine
	add := func(line string, attention bool) {
		for _, wrapped := range wrapIndentedLine(line, width) {
			out = append(out, policyApplyReviewLine{text: wrapped, attention: attention})
		}
	}
	if apply.applyErr != "" {
		for _, line := range strings.Split(apply.applyErr, "\n") {
			add(line, true)
		}
		add("", false)
	}
	for _, line := range apply.warnings {
		add(line, true)
	}
	if len(apply.warnings) > 0 {
		add("", false)
	}
	for _, line := range apply.diffLines {
		add(line, strings.HasPrefix(strings.TrimSpace(line), "loosened"))
	}
	return out
}

// wrapIndentedLine wraps one line to width, keeping its indentation and
// indenting continuation lines one step further.
func wrapIndentedLine(line string, width int) []string {
	trimmed := strings.TrimLeft(line, " ")
	indent := line[:len(line)-len(trimmed)]
	if trimmed == "" || len(line) <= width || width <= len(indent)+10 {
		return []string{line}
	}
	parts := strings.Split(wrapPlainText(trimmed, width-len(indent)-2), "\n")
	for i := range parts {
		if i == 0 {
			parts[i] = indent + parts[i]
		} else {
			parts[i] = indent + "  " + parts[i]
		}
	}
	return parts
}

func (m Model) policyApplyVisibleLines() int {
	if m.height <= 0 {
		return 20
	}
	if visible := m.height - 10; visible > 1 {
		return visible
	}
	return 1
}

func (m Model) renderPolicyApplyForm() string {
	apply := m.policies.apply
	var body strings.Builder
	body.WriteString(titleStyle.Render("Load Policy File"))
	body.WriteString("\n\n")
	if m.policies.policy.NodeRole == "cosigner" {
		body.WriteString(subtitleStyle.Render("The file's \"key\" field names the cosigner key it governs; the node must hold that key."))
	} else {
		body.WriteString(subtitleStyle.Render("The file replaces this node's policy.json."))
	}
	body.WriteString("\n\n")
	body.WriteString("Policy file:\n")
	body.WriteString(inputActiveStyle.Width(m.constrainParameterFieldWidth(60)).Render(apply.path))
	body.WriteString("\n" + helpStyle.Render("The file is checked and its changes shown before anything is applied."))
	body.WriteString("\n")
	if apply.busy != "" {
		body.WriteString("\n")
		body.WriteString(subtitleStyle.Render(apply.busy))
		body.WriteString("\n")
	}
	if apply.err != "" {
		body.WriteString("\n")
		body.WriteString(errorStyle.Render(wrapPlainText(apply.err, m.popupBodyWidth(90))))
		body.WriteString("\n")
	}
	for _, line := range apply.problems {
		body.WriteString(wrapPlainText(line, m.popupBodyWidth(90)))
		body.WriteString("\n")
	}
	return m.renderPopup(90, body.String())
}

func (m Model) renderPolicyApplyReview() string {
	apply := m.policies.apply
	width := m.policyApplyReviewWidth()
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Review Policy Change"))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render(ellipsize(apply.file+"  →  "+m.policyApplyTargetLabel(), width)))
	sb.WriteString("\n\n")

	lines := m.policyApplyReviewLines()
	offset := max(0, min(apply.scrollOffset, len(lines)))
	end := min(offset+m.policyApplyVisibleLines(), len(lines))
	if offset > 0 {
		sb.WriteString(scrollMoreAboveLine(offset))
		sb.WriteString("\n")
	}
	for _, line := range lines[offset:end] {
		if line.attention {
			sb.WriteString(warningStyle.Render(line.text))
		} else {
			sb.WriteString(line.text)
		}
		sb.WriteString("\n")
	}
	if end < len(lines) {
		sb.WriteString(scrollMoreBelowLine(len(lines) - end))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	switch {
	case apply.applying:
		sb.WriteString(subtitleStyle.Render("Applying policy..."))
	case apply.applyErr != "":
		sb.WriteString(errorStyle.Render("Nothing more can be applied from this review; go back and load the file again."))
	case apply.unchanged:
		sb.WriteString(subtitleStyle.Render("Policy unchanged; there is nothing to apply."))
	default:
		sb.WriteString(warningStyle.Render("Apply these changes? The node stores the file's exact bytes and activates them immediately."))
	}
	sb.WriteString("\n")
	return sb.String()
}

func (m Model) policyApplyFooterText() string {
	apply := m.policies.apply
	if m.viewState == ViewPolicyApplyForm {
		if apply.busy != "" {
			return "Esc: Cancel"
		}
		return "Enter: Check and review | Esc: Back"
	}
	if apply.applying {
		return "Applying..."
	}
	footer := "n/esc: Cancel"
	if apply.unchanged || apply.applyErr != "" {
		footer = "esc: Back"
	} else {
		footer = "y: Apply | " + footer
	}
	if len(m.policyApplyReviewLines()) > m.policyApplyVisibleLines() {
		footer += " | up/down/pgup/pgdown: Scroll"
	}
	return footer
}

// SendCheckPolicy asks the daemon to validate one candidate document.
func (c *IPCClient) SendCheckPolicy(doc adminproto.PolicyDocument, id string) error {
	return c.sendMessage(protocol.CheckPolicyMessage{
		BaseMessage: BaseMessage{Type: protocol.MsgTypeCheckPolicy, ID: id},
		Documents:   []protocol.PolicyDocumentWire{{Key: doc.Key, Document: doc.Document}},
	})
}

func (m Model) sendCheckPolicyCmd(doc adminproto.PolicyDocument, id string) tea.Cmd {
	return policyRequestCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendCheckPolicy(doc, id) })
}

// SendApplyPolicy asks the daemon to install one document against the policy
// set the operator reviewed.
func (c *IPCClient) SendApplyPolicy(doc adminproto.PolicyDocument, expectedPolicySetSHA256, id string) error {
	return c.sendMessage(protocol.ApplyPolicyMessage{
		BaseMessage:             BaseMessage{Type: protocol.MsgTypeApplyPolicy, ID: id},
		Documents:               []protocol.PolicyDocumentWire{{Key: doc.Key, Document: doc.Document}},
		ExpectedPolicySetSHA256: expectedPolicySetSHA256,
	})
}

func (m Model) sendApplyPolicyCmd(doc adminproto.PolicyDocument, expectedPolicySetSHA256, id string) tea.Cmd {
	return policyRequestCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendApplyPolicy(doc, expectedPolicySetSHA256, id) })
}
