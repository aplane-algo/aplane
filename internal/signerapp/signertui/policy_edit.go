// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyreview"
	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
)

// The policy editor changes one policy document's JSON in place. It is a
// second source for the workflow in policy_apply.go: the edited text goes
// through the same daemon check, diff review, and confirmed apply as a loaded
// file, and nothing is stored until that apply. A key that has no document
// of its own opens on the node default with its key filled in, so an edit
// always starts from exactly what the key was already doing.
//
// The text may carry // and /* */ comments; policyreview removes them before
// the document reaches the node.

// policyEditMaxLines is the text area's fixed capacity for inserted text.
// Setting its value or pasting drops every line past this count without
// notice, whatever its height settings, so the editor refuses a document that
// does not fit and reports a paste that was cut short.
const policyEditMaxLines = 10000

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
	// key is the document being edited: "default" or a key selector.
	key string
	// isNew reports that the key had no document of its own and the editor
	// opened on the node default with the key filled in.
	isNew bool
	// templateFor, while loading, names the key a template is being built
	// for from the default document being fetched.
	templateFor string
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
	// The defaults cap the displayed editor at 99 rows and 500 columns. They
	// do not lift policyEditMaxLines.
	input.MaxHeight = 0
	input.MaxWidth = 0
	input.Cursor.SetMode(cursor.CursorStatic)
	// Pasted text arrives from the terminal as key input. The component's own
	// ctrl+v binding would instead read this machine's clipboard through an
	// external helper program, and its answer is a message this view never
	// receives; an admin console should not run that helper at all.
	input.KeyMap.Paste.SetEnabled(false)
	return input
}

// policyTextEquivalent reports whether the editor holds the whole document.
// The text area may normalize whitespace, which changes nothing a policy
// says, so JSON documents are compared without it or their comments.
func policyTextEquivalent(document, held string) bool {
	var want, got bytes.Buffer
	if json.Compact(&want, policyJSONBytes(document)) != nil || json.Compact(&got, policyJSONBytes(held)) != nil {
		return strings.TrimSpace(document) == strings.TrimSpace(held)
	}
	return bytes.Equal(want.Bytes(), got.Bytes())
}

// policyJSONBytes is text with its comments blanked, for JSON tools that
// only need to see the JSON. Text whose comments cannot be blanked is
// returned as is, for the tool to reject.
func policyJSONBytes(text string) []byte {
	blanked, err := policyreview.BlankComments([]byte(text))
	if err != nil {
		return []byte(text)
	}
	return blanked
}

// policyEditLabel names the edited document in problems, diffs, and status.
func policyEditLabel(key string) string {
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

// openPolicyEditForRow edits the document of the selected list row. A key
// without a document of its own opens on the node default with the key
// filled in, fetched from the daemon so it is the node's current default.
func (m Model) openPolicyEditForRow(row policyRow) (tea.Model, tea.Cmd) {
	if !m.policyEditAvailable() {
		return m, nil
	}
	key := row.key
	if key != policy.DefaultKey && !m.policyKeyHeld(key) {
		m.policies.status = fmt.Sprintf("This node does not hold key %s; generate or import the key before editing its policy.", key)
		return m, nil
	}
	edit := policyEditState{active: true, loading: true, key: key, pendingDocumentID: newRequestID("policy-edit-doc")}
	fetchKey := key
	if row.doc == nil {
		edit.templateFor = key
		fetchKey = policy.DefaultKey
	}
	m.policies.apply = policyApplyState{edit: edit}
	m.policies.status = ""
	m.viewState = ViewPolicyEdit
	id := edit.pendingDocumentID
	return m, tea.Batch(
		policyRequestCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendGetPolicyDocument(fetchKey, id) }),
		m.waitForMessageCmd(),
	)
}

// openPolicyEditForDocument edits the document shown in the document view.
func (m Model) openPolicyEditForDocument() (tea.Model, tea.Cmd) {
	doc := m.policies.document
	if !m.policyEditAvailable() || m.policies.docLoading || !doc.Success {
		return m, nil
	}
	if doc.Key != policy.DefaultKey && !m.policyKeyHeld(doc.Key) {
		m.policies.status = fmt.Sprintf("This node does not hold key %s; generate or import the key before editing its policy.", doc.Key)
		m.viewState = ViewPolicies
		return m, nil
	}
	return m.startPolicyEditor(doc.Key, doc.Document, false), nil
}

func (m Model) handlePolicyEditDocumentLoaded(msg PolicyDocumentLoadedMsg) (tea.Model, tea.Cmd) {
	edit := m.policies.apply.edit
	if !msg.Document.Success {
		detail := policyResultError(msg.Document.Code, msg.Document.Error, "document is unavailable")
		m = m.closePolicyApply()
		m.policies.status = "Could not open the policy for editing: " + detail
		return m, m.waitForMessageCmd()
	}
	if edit.templateFor != "" {
		role, err := noderole.ParseRole(m.policies.policy.NodeRole)
		var template string
		if err == nil {
			template, err = policyreview.Template(role, edit.templateFor, []byte(msg.Document.Document))
		}
		if err != nil {
			m = m.closePolicyApply()
			m.policies.status = "Cannot start a policy for this key from the node default: " + err.Error()
			return m, m.waitForMessageCmd()
		}
		return m.startPolicyEditor(edit.templateFor, template, true), m.waitForMessageCmd()
	}
	return m.startPolicyEditor(edit.key, msg.Document.Document, false), m.waitForMessageCmd()
}

// startPolicyEditor opens the editor on text with the cursor at the top. A
// document the editor cannot hold completely is not opened: editing a
// silently shortened copy would look unmodified and could be applied.
func (m Model) startPolicyEditor(key, document string, isNew bool) Model {
	input := newPolicyEditorInput()
	text := editablePolicyText(document)
	input.SetValue(text)
	if !policyTextEquivalent(text, input.Value()) {
		m = m.closePolicyApply()
		m.policies.status = fmt.Sprintf(
			"This policy is too large to edit here (more than %d lines). Export it with apadmin policy export, edit the file, and load it with a.",
			policyEditMaxLines,
		)
		return m
	}
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
	linesBefore := input.LineCount()
	pastedLines := strings.Count(string(msg.Runes), "\n")
	var cmd tea.Cmd
	edit.input, cmd = input.Update(msg)
	switch {
	case edit.input.LineCount() < linesBefore+pastedLines:
		apply.problems = nil
		apply.err = fmt.Sprintf("That paste would take the text past %d lines, so its end was not inserted. Check the end of the text.", policyEditMaxLines)
	case edit.input.Length() >= policyreview.MaxPolicyBytes:
		apply.problems = nil
		apply.err = fmt.Sprintf("The editor is full: a policy document is at most %d bytes.", policyreview.MaxPolicyBytes)
	}
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
	// The review is built from the policy summary: whether the key has an
	// active document to diff against, and the policy set the apply names. A
	// summary that is still reloading is not yet the node's current state.
	if m.policies.loading {
		apply.err = "The policy summary is reloading; press ctrl+s again in a moment."
		return m, nil
	}
	if m.policies.err != "" || !m.policies.policy.Success {
		apply.err = "The policy summary is unavailable; press esc and reopen Policies."
		return m, nil
	}
	text := strings.TrimRight(edit.input.Value(), "\n") + "\n"
	if _, err := policyreview.BlankComments([]byte(text)); err != nil {
		apply.err = "Invalid JSON: " + err.Error()
		return m, nil
	}
	if problem := policyJSONSyntaxError(text); problem != "" {
		apply.err = problem
		return m, nil
	}
	label := policyEditLabel(edit.key)
	doc, err := policyreview.DocumentFromText(label, text)
	if err != nil {
		apply.err = err.Error()
		return m, nil
	}
	if doc.Key != edit.key {
		apply.err = fmt.Sprintf("The \"key\" field must stay %s. This editor changes that document; load a file to set another key's.", edit.key)
		return m, nil
	}
	apply.doc = doc
	apply.file = label
	apply.busy = "Checking policy..."
	apply.pendingCheckID = newRequestID("policy-check")
	return m, tea.Batch(m.sendCheckPolicyCmd(doc, apply.pendingCheckID), m.waitForMessageCmd())
}

// policyJSONSyntaxError reports a JSON syntax error with its line and column,
// or "" when text parses. Comments are blanked in place first, so the line
// and column are those of the text as the operator sees it.
func policyJSONSyntaxError(text string) string {
	var value any
	err := json.Unmarshal(policyJSONBytes(text), &value)
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
		hint = "No policy of its own yet: this is the node default with the key filled in. Applying it gives the key its own policy; comments are removed on apply."
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
	return policyTargetLabel(m.policies.apply.edit.key)
}

// policyTargetLabel names the document a workflow acts on.
func policyTargetLabel(key string) string {
	if key == policy.DefaultKey {
		return "node default policy"
	}
	return "key " + key
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
