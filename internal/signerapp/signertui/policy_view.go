// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// The policies view lists the node's active policy documents and shows their
// exact bytes. A document changes only through the workflow in
// policy_apply.go, which takes a policy file or an edit from policy_edit.go
// through the same check, diff, and apply steps as apadmin policy apply.

// policiesState is the policy list, the document viewer, and the
// load-policy-file workflow.
type policiesState struct {
	loading      bool
	err          string
	policy       protocol.PolicyMessage
	selected     int
	scrollOffset int
	returnView   ViewState
	document     protocol.PolicyDocumentMessage
	docLoading   bool
	// pendingPolicyID and pendingDocumentID name the requests this view is
	// waiting for; responses to any other request are stale and ignored.
	pendingPolicyID   string
	pendingDocumentID string
	// snapshot is the composite snapshot (policy set plus context) of the
	// summary shown, set only once the context read describes the same
	// policy set; an apply names it. pendingContextID and loadedContext pair
	// the two reads, which can arrive in either order.
	snapshot         string
	pendingContextID string
	loadedContext    *PolicyContextMessage
	// status reports the last apply on the list.
	status string
	apply  policyApplyState
	export policyExportState
	// presetPick is the starting-text picker shown before the editor.
	presetPick policyPresetPickState
}

func newRequestID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// PolicyDocumentLoadedMsg carries the daemon's response for one document.
type PolicyDocumentLoadedMsg struct {
	Document protocol.PolicyDocumentMessage
}

// PolicyContextLoadedMsg carries the daemon's policy context response.
type PolicyContextLoadedMsg struct {
	Context PolicyContextMessage
}

// PolicyLoadedMsg carries the daemon's policy response.
type PolicyLoadedMsg struct {
	Policy protocol.PolicyMessage
}

// policyRow is one line of the policies list: the node default first, then
// every held key with its coverage, then documents for keys not held.
type policyRow struct {
	// key is the document key the row stands for: "default" or a selector.
	key    string
	status string
	doc    *protocol.PolicyDocumentInfoWire
}

func (r policyRow) label() string {
	if r.key == policy.DefaultKey {
		return "default"
	}
	return r.key
}

func (m Model) openPolicies() (tea.Model, tea.Cmd) {
	m.policies = policiesState{returnView: m.viewState}
	m.viewState = ViewPolicies
	return m.requestPolicy()
}

func (m Model) requestPolicy() (tea.Model, tea.Cmd) {
	m.policies.loading = true
	m.policies.pendingPolicyID = newRequestID("policy")
	m.policies.pendingContextID = newRequestID("policy-context")
	m.policies.snapshot, m.policies.loadedContext = "", nil
	contextID := m.policies.pendingContextID
	return m, tea.Batch(
		m.sendGetPolicyCmd(m.policies.pendingPolicyID),
		ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendGetPolicyContext(contextID) }),
		m.waitForMessageCmd(),
	)
}

// handlePolicyContextLoaded receives the context read paired with the
// summary.
func (m Model) handlePolicyContextLoaded(msg PolicyContextLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.Context.ID == "" || msg.Context.ID != m.policies.pendingContextID {
		return m, m.waitForMessageCmd()
	}
	m.policies.pendingContextID = ""
	ctx := msg.Context
	m.policies.loadedContext = &ctx
	return m.settlePolicySnapshot()
}

// settlePolicySnapshot pairs the summary and the context once both arrived.
// They describe one state only when the context names the summary's policy
// set; otherwise the policy moved between the reads and both are read again.
func (m Model) settlePolicySnapshot() (tea.Model, tea.Cmd) {
	ctx := m.policies.loadedContext
	if m.policies.pendingPolicyID != "" || ctx == nil {
		return m, m.waitForMessageCmd()
	}
	if !ctx.Success || !m.policies.policy.Success {
		return m, m.waitForMessageCmd()
	}
	if ctx.PolicySetSHA256 != m.policies.policy.PolicySetSHA256 {
		return m.requestPolicy()
	}
	m.policies.snapshot = ctx.SnapshotSHA256
	return m, m.waitForMessageCmd()
}

func (m Model) handlePolicyLoaded(msg PolicyLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.Policy.ID == "" || msg.Policy.ID != m.policies.pendingPolicyID {
		return m, m.waitForMessageCmd()
	}
	m.policies.pendingPolicyID = ""
	m.policies.loading = false
	m.policies.policy = msg.Policy
	m.policies.err = ""
	if !msg.Policy.Success {
		m.policies.err = msg.Policy.Error
		if m.policies.err == "" {
			m.policies.err = "policy is unavailable"
		}
	}
	if rows := m.policyRows(); m.policies.selected >= len(rows) {
		m.policies.selected = 0
	}
	return m.settlePolicySnapshot()
}

func (m Model) policyRows() []policyRow {
	p := m.policies.policy
	byKey := make(map[string]*protocol.PolicyDocumentInfoWire, len(p.Documents))
	for i := range p.Documents {
		byKey[p.Documents[i].Key] = &p.Documents[i]
	}
	rows := make([]policyRow, 0, 1+len(p.Keys))
	if doc := byKey[policy.DefaultKey]; doc != nil {
		rows = append(rows, policyRow{key: policy.DefaultKey, status: policy.DefaultKey, doc: doc})
	}
	for _, key := range p.Keys {
		rows = append(rows, policyRow{key: key.Key, status: key.Status, doc: byKey[key.Key]})
	}
	return rows
}

func (m Model) handlePoliciesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.policyRows()
	switch msg.String() {
	case "esc", "q":
		m.viewState = m.policies.returnView
		m.policies = policiesState{}
		return m, nil
	case "r":
		m.policies.status = ""
		return m.requestPolicy()
	case "a":
		return m.openPolicyApply()
	case "x":
		return m.openPolicyExport()
	case "e":
		if m.policies.selected < len(rows) {
			return m.openPolicyPresetPick(rows[m.policies.selected])
		}
	case "up", "k":
		if m.policies.selected > 0 {
			m.policies.selected--
		}
	case "down", "j":
		if m.policies.selected < len(rows)-1 {
			m.policies.selected++
		}
	case "enter":
		if m.policies.selected < len(rows) && rows[m.policies.selected].doc != nil {
			m.policies.scrollOffset = 0
			m.policies.document = protocol.PolicyDocumentMessage{}
			m.policies.docLoading = true
			m.policies.pendingDocumentID = newRequestID("policy-doc")
			m.viewState = ViewPolicyDocument
			key := rows[m.policies.selected].doc.Key
			return m, tea.Batch(m.sendGetPolicyDocumentCmd(key, m.policies.pendingDocumentID), m.waitForMessageCmd())
		}
	}
	return m, nil
}

func (m Model) handlePolicyDocumentLoaded(msg PolicyDocumentLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.Document.ID != "" && msg.Document.ID == m.policies.export.pendingID {
		return m.handlePolicyExportDocumentLoaded(msg)
	}
	if msg.Document.ID != "" && msg.Document.ID == m.policies.apply.pendingDocumentID {
		return m.handlePolicyApplyDocumentLoaded(msg)
	}
	if msg.Document.ID != "" && msg.Document.ID == m.policies.apply.edit.pendingDocumentID {
		return m.handlePolicyEditDocumentLoaded(msg)
	}
	if msg.Document.ID == "" || msg.Document.ID != m.policies.pendingDocumentID {
		return m, m.waitForMessageCmd()
	}
	m.policies.pendingDocumentID = ""
	m.policies.docLoading = false
	m.policies.document = msg.Document
	return m, m.waitForMessageCmd()
}

func (m Model) policyDocumentLines() []string {
	doc := m.policies.document
	if m.policies.docLoading || !doc.Success {
		return nil
	}
	return strings.Split(strings.TrimRight(doc.Document, "\n"), "\n")
}

func (m Model) policyDocumentVisibleLines() int {
	if m.height <= 0 {
		return 20
	}
	if visible := m.height - 8; visible > 1 {
		return visible
	}
	return 1
}

func (m Model) handlePolicyDocumentKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	maxOffset := len(m.policyDocumentLines()) - m.policyDocumentVisibleLines()
	if maxOffset < 0 {
		maxOffset = 0
	}
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewPolicies
		m.policies.scrollOffset = 0
		m.policies.pendingDocumentID = ""
		m.policies.docLoading = false
	case "e":
		return m.openPolicyEditForDocument()
	case "up", "k":
		m.policies.scrollOffset--
	case "down", "j":
		m.policies.scrollOffset++
	case "pgup":
		m.policies.scrollOffset -= m.policyDocumentVisibleLines()
	case "pgdown":
		m.policies.scrollOffset += m.policyDocumentVisibleLines()
	}
	m.policies.scrollOffset = max(0, min(m.policies.scrollOffset, maxOffset))
	return m, nil
}

func (m Model) renderPolicies() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Policies"))
	sb.WriteString("\n")
	switch {
	case m.policies.loading:
		sb.WriteString(subtitleStyle.Render("Loading policy..."))
		return sb.String()
	case m.policies.err != "":
		sb.WriteString(subtitleStyle.Render("Policy unavailable: " + m.policies.err))
		return sb.String()
	}
	p := m.policies.policy
	sb.WriteString(subtitleStyle.Render(fmt.Sprintf("%s node  ·  e edits the selected policy; a loads a policy file; x exports the policy; apadmin policy covers remove and rescue", p.NodeRole)))
	sb.WriteString("\n\n")
	rows := m.policyRows()
	if len(rows) == 0 {
		sb.WriteString("No policy documents.\n")
	}
	for i, row := range rows {
		cursor := "  "
		if i == m.policies.selected {
			cursor = "> "
		}
		sb.WriteString(cursor + row.label() + "  " + policyStatusLabel(row.key, row.status))
		if row.doc != nil {
			sb.WriteString("  " + policyDocumentMeta(*row.doc))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("policy_set_sha256 " + p.PolicySetSHA256))
	sb.WriteString("\n")
	if m.policies.status != "" {
		sb.WriteString("\n")
		sb.WriteString(m.policies.status)
		sb.WriteString("\n")
	}
	return sb.String()
}

func policyStatusLabel(key, status string) string {
	switch {
	case key == policy.DefaultKey:
		return "node default (governs every key without its own policy)"
	case status == adminproto.PolicyKeyOwn:
		return "own policy"
	case status == adminproto.PolicyKeyNotHeld:
		return "policy, key not held"
	default:
		return "default"
	}
}

func policyDocumentMeta(doc protocol.PolicyDocumentInfoWire) string {
	meta := fmt.Sprintf("%d bytes  sha256 %s", doc.Size, shortDigest(doc.SHA256))
	if doc.SignedAtUnix > 0 {
		meta += "  applied " + time.Unix(doc.SignedAtUnix, 0).UTC().Format("2006-01-02 15:04Z")
	}
	return meta
}

func shortDigest(digest string) string {
	if len(digest) > 16 {
		return digest[:16] + "…"
	}
	return digest
}

func (m Model) renderPolicyDocument() string {
	width := m.width
	if width < 20 {
		width = 80
	}
	doc := m.policies.document
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Policy Document"))
	sb.WriteString("\n")
	switch {
	case m.policies.docLoading:
		sb.WriteString(subtitleStyle.Render("Loading document..."))
		return sb.String()
	case !doc.Success:
		msg := doc.Error
		if msg == "" {
			msg = "document is unavailable"
		}
		sb.WriteString(subtitleStyle.Render("Document unavailable: " + msg))
		return sb.String()
	}
	sb.WriteString(subtitleStyle.Render(ellipsize(doc.Key+"  sha256 "+doc.SHA256, width)))
	sb.WriteString("\n\n")

	lines := m.policyDocumentLines()
	offset := max(0, min(m.policies.scrollOffset, len(lines)))
	end := min(offset+m.policyDocumentVisibleLines(), len(lines))
	if offset > 0 {
		sb.WriteString(scrollMoreAboveLine(offset))
		sb.WriteString("\n")
	}
	for _, line := range lines[offset:end] {
		sb.WriteString(ellipsize(line, width))
		sb.WriteString("\n")
	}
	if end < len(lines) {
		sb.WriteString(scrollMoreBelowLine(len(lines) - end))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m Model) policiesFooterText() string {
	if m.viewState == ViewPolicyDocument {
		footer := "e: Edit | esc/q: Back"
		if len(m.policyDocumentLines()) > m.policyDocumentVisibleLines() {
			footer += " | up/down/pgup/pgdown: Scroll"
		}
		return footer
	}
	return "up/down: Select | enter: View | e: Edit | a: Load file | x: Export | r: Refresh | esc/q: Back"
}

// SendGetPolicy requests the node's policy summary under request id.
func (c *IPCClient) SendGetPolicy(id string) error {
	return c.sendMessage(protocol.GetPolicyMessage{
		BaseMessage: BaseMessage{Type: protocol.MsgTypeGetPolicy, ID: id},
	})
}

func (m Model) sendGetPolicyCmd(id string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendGetPolicy(id) })
}

// SendGetPolicyContext requests the node's policy context under request id.
func (c *IPCClient) SendGetPolicyContext(id string) error {
	return c.sendMessage(protocol.GetPolicyContextMessage{BaseMessage: BaseMessage{Type: protocol.MsgTypeGetPolicyContext, ID: id}})
}

// SendGetPolicyDocumentAt requests one policy document under request id,
// refused by the node if its policy or context moved since snapshot.
func (c *IPCClient) SendGetPolicyDocumentAt(key, snapshot, id string) error {
	return c.sendMessage(protocol.GetPolicyDocumentMessage{
		BaseMessage:            BaseMessage{Type: protocol.MsgTypeGetPolicyDocument, ID: id},
		Key:                    key,
		ExpectedSnapshotSHA256: snapshot,
	})
}

// SendGetPolicyDocument requests one policy document under request id.
func (c *IPCClient) SendGetPolicyDocument(key, id string) error {
	return c.sendMessage(protocol.GetPolicyDocumentMessage{
		BaseMessage: BaseMessage{Type: protocol.MsgTypeGetPolicyDocument, ID: id},
		Key:         key,
	})
}

func (m Model) sendGetPolicyDocumentCmd(key, id string) tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendGetPolicyDocument(key, id) })
}
