// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyreview"
	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
)

// The policy editor changes one policy document's JSON in place. It is a
// second source for the workflow in policy_apply.go: the edited text goes
// through the same daemon check, diff review, and confirmed apply as a loaded
// file, and nothing is stored until that apply. A cosigner key that has no
// document yet opens on the locked starting document, which rejects every
// request, so an edit always starts from zero permissions.

// policyEditMaxProblemLines bounds the lines of check problems shown under
// the editor, so a long list cannot push the text off the screen. The first
// problem is always shown in full.
const policyEditMaxProblemLines = 8

// policyEditState is the editor half of the apply workflow.
type policyEditState struct {
	// active reports that the candidate comes from the editor, not a file.
	active bool
	// loading reports that the editor is waiting for the active document.
	loading bool
	// key is the cosigner key whose policy is edited; empty on a signer node.
	key string
	// isNew reports that the key had no document and the editor opened on the
	// locked starting document.
	isNew bool
	// original is the text the editor opened with, for the discard check.
	original string
	input    textarea.Model
	// confirmDiscard reports that esc was pressed once on changed text.
	confirmDiscard bool
	// pendingDocumentID names the document request the editor is waiting on.
	pendingDocumentID string
}

func newPolicyEditorInput() textarea.Model {
	input := textarea.New()
	input.Prompt = ""
	input.ShowLineNumbers = true
	input.EndOfBufferCharacter = ' '
	input.CharLimit = policyreview.MaxPolicyBytes
	// The defaults cap the editor at 99 rows and 500 columns.
	input.MaxHeight = 0
	input.MaxWidth = 0
	input.Cursor.SetMode(cursor.CursorStatic)
	return input
}

// policyEditLabel names the edited document in problems, diffs, and status.
func policyEditLabel(key string) string {
	if key == "" {
		return "policy.json"
	}
	return key + ".json"
}

// editablePolicyText lays a stored document out for editing. The node stores
// exact bytes, which may be one long line; whitespace does not change what a
// policy allows, so a single-line document is indented.
func editablePolicyText(document string) string {
	trimmed := strings.TrimSpace(document)
	if !strings.Contains(trimmed, "\n") {
		var indented bytes.Buffer
		if err := json.Indent(&indented, []byte(trimmed), "", "  "); err == nil {
			return indented.String()
		}
	}
	return strings.TrimRight(document, "\n")
}

// policyEditAvailable reports whether the policy summary is loaded and usable.
func (m Model) policyEditAvailable() bool {
	return !m.policies.loading && m.policies.err == "" && m.policies.policy.Success
}

// openPolicyEditForRow edits the document of the selected list row. A cosigner
// key without a document opens on the locked starting document.
func (m Model) openPolicyEditForRow(row policyRow) (tea.Model, tea.Cmd) {
	if !m.policyEditAvailable() {
		return m, nil
	}
	key := ""
	if m.policies.policy.NodeRole == "cosigner" {
		key = row.label
		if !m.policyKeyHeld(key) {
			m.policies.status = fmt.Sprintf("This node does not hold cosigner key %s; generate the key before editing its policy.", key)
			return m, nil
		}
	}
	if row.doc == nil {
		document, err := policy.LockedCosignerDocumentV1(key)
		if err != nil {
			m.policies.status = "Cannot start a policy for this key: " + err.Error()
			return m, nil
		}
		return m.startPolicyEditor(key, document, true), nil
	}
	m.policies.apply = policyApplyState{edit: policyEditState{
		active: true, loading: true, key: key, pendingDocumentID: newRequestID("policy-edit-doc"),
	}}
	m.policies.status = ""
	m.viewState = ViewPolicyEdit
	id := m.policies.apply.edit.pendingDocumentID
	return m, tea.Batch(
		policyRequestCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendGetPolicyDocument(key, id) }),
		m.waitForMessageCmd(),
	)
}

// openPolicyEditForDocument edits the document shown in the document view.
func (m Model) openPolicyEditForDocument() (tea.Model, tea.Cmd) {
	doc := m.policies.document
	if !m.policyEditAvailable() || m.policies.docLoading || !doc.Success {
		return m, nil
	}
	if m.policies.policy.NodeRole == "cosigner" && !m.policyKeyHeld(doc.Key) {
		m.policies.status = fmt.Sprintf("This node does not hold cosigner key %s; generate the key before editing its policy.", doc.Key)
		m.viewState = ViewPolicies
		return m, nil
	}
	return m.startPolicyEditor(doc.Key, doc.Document, false), nil
}

func (m Model) handlePolicyEditDocumentLoaded(msg PolicyDocumentLoadedMsg) (tea.Model, tea.Cmd) {
	key := m.policies.apply.edit.key
	if !msg.Document.Success {
		detail := policyResultError(msg.Document.Code, msg.Document.Error, "document is unavailable")
		m = m.closePolicyApply()
		m.policies.status = "Could not open the policy for editing: " + detail
		return m, m.waitForMessageCmd()
	}
	return m.startPolicyEditor(key, msg.Document.Document, false), m.waitForMessageCmd()
}

// startPolicyEditor opens the editor on text with the cursor at the top.
func (m Model) startPolicyEditor(key, document string, isNew bool) Model {
	input := newPolicyEditorInput()
	input.SetValue(editablePolicyText(document))
	_ = input.Focus()
	input, _ = input.Update(tea.KeyMsg{Type: tea.KeyCtrlHome})
	m.policies.apply = policyApplyState{edit: policyEditState{
		active: true, key: key, isNew: isNew, original: input.Value(), input: input,
	}}
	m.policies.status = ""
	m.viewState = ViewPolicyEdit
	return m
}

// returnToPolicyEditor leaves the review for the editor with the text intact.
func (m Model) returnToPolicyEditor() Model {
	apply := &m.policies.apply
	apply.warnings = nil
	apply.diffLines = nil
	apply.unchanged = false
	apply.applying = false
	apply.applyErr = ""
	apply.scrollOffset = 0
	apply.pendingApplyID = ""
	m.viewState = ViewPolicyEdit
	return m
}

func (m Model) handlePolicyEditKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	apply := &m.policies.apply
	edit := &apply.edit
	if edit.loading {
		if msg.String() == "esc" {
			return m.closePolicyApply(), nil
		}
		return m, nil
	}
	if apply.busy != "" {
		if msg.String() == "esc" {
			// Stop waiting for the check; the text stays for another attempt.
			apply.busy = ""
			apply.pendingCheckID = ""
			apply.pendingDocumentID = ""
		}
		return m, nil
	}
	switch msg.String() {
	case "ctrl+s":
		edit.confirmDiscard = false
		return m.submitPolicyEdit()
	case "esc":
		if edit.confirmDiscard || edit.input.Value() == edit.original {
			return m.closePolicyApply(), nil
		}
		edit.confirmDiscard = true
		return m, nil
	}
	edit.confirmDiscard = false
	if msg.Type == tea.KeySpace {
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}}
	}
	input := m.sizedPolicyEditor()
	var cmd tea.Cmd
	edit.input, cmd = input.Update(msg)
	return m, cmd
}

// submitPolicyEdit sends the edited text to the daemon's policy check. Syntax
// and the key binding are checked here first, where the answer is immediate
// and can name a line.
func (m Model) submitPolicyEdit() (tea.Model, tea.Cmd) {
	apply := &m.policies.apply
	edit := &apply.edit
	apply.problems = nil
	apply.err = ""
	if !m.policies.policy.Success {
		apply.err = "The policy summary is unavailable; press esc and reopen Policies."
		return m, nil
	}
	text := strings.TrimRight(edit.input.Value(), "\n") + "\n"
	if problem := policyJSONSyntaxError(text); problem != "" {
		apply.err = problem
		return m, nil
	}
	label := policyEditLabel(edit.key)
	doc, err := policyreview.DocumentFromText(m.policies.policy.NodeRole, label, text)
	if err != nil {
		apply.err = err.Error()
		return m, nil
	}
	if doc.Key != edit.key {
		apply.err = fmt.Sprintf("The \"key\" field must stay %s. This editor changes that key's policy; load a file to set another key's.", edit.key)
		return m, nil
	}
	apply.doc = doc
	apply.file = label
	apply.busy = "Checking policy..."
	apply.pendingCheckID = newRequestID("policy-check")
	return m, tea.Batch(m.sendCheckPolicyCmd(doc, apply.pendingCheckID), m.waitForMessageCmd())
}

// policyJSONSyntaxError reports a JSON syntax error with its line and column,
// or "" when text parses.
func policyJSONSyntaxError(text string) string {
	var value any
	err := json.Unmarshal([]byte(text), &value)
	if err == nil {
		return ""
	}
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		return "Invalid JSON: " + err.Error()
	}
	offset := int(min(max(syntax.Offset, 0), int64(len(text))))
	before := text[:offset]
	line := strings.Count(before, "\n") + 1
	column := len([]rune(before[strings.LastIndex(before, "\n")+1:]))
	if column < 1 {
		column = 1
	}
	return fmt.Sprintf("Invalid JSON at line %d, column %d: %v", line, column, err)
}

// policyEditMessages is what the editor shows under the text: a pending
// discard, the request in flight, and the last check's error and problems.
func (m Model) policyEditMessages() []policyApplyReviewLine {
	apply := m.policies.apply
	width := m.policyApplyReviewWidth()
	var out []policyApplyReviewLine
	if apply.edit.confirmDiscard {
		out = append(out, policyApplyReviewLine{text: "Discard your changes? Press esc again to discard, or any other key to keep editing.", attention: true})
	}
	if apply.busy != "" {
		out = append(out, policyApplyReviewLine{text: apply.busy})
	}
	if apply.err != "" {
		for _, line := range strings.Split(wrapPlainText(apply.err, width), "\n") {
			out = append(out, policyApplyReviewLine{text: line, attention: true})
		}
	}
	// Problems are wrapped, not cut: the end of the line is the explanation.
	shown := 0
	for i, problem := range apply.problems {
		wrapped := wrapIndentedLine(problem, width)
		if shown > 0 && shown+len(wrapped) > policyEditMaxProblemLines {
			out = append(out, policyApplyReviewLine{text: fmt.Sprintf("… and %d more; fix these and check again", len(apply.problems)-i)})
			break
		}
		for _, line := range wrapped {
			out = append(out, policyApplyReviewLine{text: line})
		}
		shown += len(wrapped)
	}
	return out
}

// sizedPolicyEditor returns the editor fitted to the space left by the header
// and the messages under it.
func (m Model) sizedPolicyEditor() textarea.Model {
	input := m.policies.apply.edit.input
	height := 20
	if m.height > 0 {
		height = m.height - 9 - len(m.policyEditMessages())
	}
	input.SetWidth(m.policyApplyReviewWidth())
	input.SetHeight(max(height, 5))
	return input
}

func (m Model) renderPolicyEdit() string {
	edit := m.policies.apply.edit
	width := m.policyApplyReviewWidth()
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Edit Policy"))
	sb.WriteString("\n")
	if edit.loading {
		sb.WriteString(subtitleStyle.Render("Loading document..."))
		return sb.String()
	}
	sb.WriteString(subtitleStyle.Render(ellipsize(m.policyEditTargetLabel(), width)))
	sb.WriteString("\n")
	hint := "Nothing is stored until the edit is checked, reviewed, and applied."
	if edit.isNew {
		hint = "No policy yet: this starting document has no routes and rejects every request."
	}
	sb.WriteString(helpStyle.Render(ellipsize(hint, width)))
	sb.WriteString("\n\n")
	sb.WriteString(m.sizedPolicyEditor().View())
	sb.WriteString("\n")
	for _, line := range m.policyEditMessages() {
		if line.attention {
			sb.WriteString(warningStyle.Render(line.text))
		} else {
			sb.WriteString(subtitleStyle.Render(line.text))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m Model) policyEditTargetLabel() string {
	if key := m.policies.apply.edit.key; key != "" {
		return "cosigner key " + key
	}
	return "policy.json"
}

func (m Model) policyEditFooterText() string {
	apply := m.policies.apply
	switch {
	case apply.edit.loading:
		return "esc: Cancel"
	case apply.busy != "":
		return "esc: Stop waiting"
	case apply.edit.confirmDiscard:
		return "esc: Discard changes | any other key: Keep editing"
	default:
		return "ctrl+s: Check and review | esc: Cancel"
	}
}
