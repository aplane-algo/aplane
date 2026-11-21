// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
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
	// contextErr is why the context read failed, which apply and export
	// report instead of waiting for it.
	contextErr string
	// status reports the last apply on the list.
	status string
	apply  policyApplyState
	export policyExportState
	// presetPick is the starting-text picker shown before the editor.
	presetPick policyPresetPickState
}

// requestSeq numbers the request IDs this process names, so two named within
// one tick of the clock still differ.
var requestSeq atomic.Uint64

// newRequestID names a request: its prefix says what it is, and the time and
// sequence number make it distinct from every other this process sends.
func newRequestID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), requestSeq.Add(1))
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

func (m Model) openPolicies() (tea.Model, tea.Cmd) {
	m.policies = policiesState{returnView: m.viewState}
	m.viewState = ViewPolicies
	return m.requestPolicy()
}

func (m Model) requestPolicy() (tea.Model, tea.Cmd) {
	m.policies.loading = true
	m.policies.pendingPolicyID = newRequestID("policy")
	m.policies.pendingContextID = newRequestID("policy-context")
	m.policies.snapshot, m.policies.loadedContext, m.policies.contextErr = "", nil, ""
	return m, tea.Batch(
		m.sendGetPolicyCmd(m.policies.pendingPolicyID),
		m.sendGetPolicyContextCmd(m.policies.pendingContextID),
	)
}

// failPendingPolicyView settles the summary, context or document read that
// id names with err, from the daemon (an authorization denial, a node with no
// runtime bound) or from a send, so the screen shows the error rather than
// staying on Loading.
func (m Model) failPendingPolicyView(id string, err error) (Model, bool) {
	if id == "" {
		return m, false
	}
	switch id {
	case m.policies.pendingPolicyID:
		m.policies.pendingPolicyID = ""
		m.policies.loading = false
		m.policies.err = err.Error()
	case m.policies.pendingContextID:
		m.policies.pendingContextID = ""
		m.policies.contextErr = err.Error()
	case m.policies.pendingDocumentID:
		m.policies.pendingDocumentID = ""
		m.policies.docLoading = false
		m.policies.document = protocol.PolicyDocumentMessage{Error: err.Error()}
	default:
		return m, false
	}
	return m, true
}

// policyContextProblem is why apply and export cannot use the node's policy
// context, or "" when they can.
func (m Model) policyContextProblem() string {
	switch {
	case m.policies.contextErr != "":
		return "The node's policy context could not be read: " + m.policies.contextErr + ". Refresh the Policies list (r) and try again"
	case m.policies.snapshot == "" || m.policies.loadedContext == nil:
		return "The node's policy context is still loading; try again"
	}
	return ""
}

// handlePolicyContextLoaded receives the context read paired with the
// summary.
func (m Model) handlePolicyContextLoaded(msg PolicyContextLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.Context.ID == "" || msg.Context.ID != m.policies.pendingContextID {
		return m, nil
	}
	m.policies.pendingContextID = ""
	ctx := msg.Context
	m.policies.loadedContext = &ctx
	if !ctx.Success {
		m.policies.contextErr = ctx.Error
		if m.policies.contextErr == "" {
			m.policies.contextErr = "policy context is unavailable"
		}
	}
	return m.settlePolicySnapshot()
}

// settlePolicySnapshot pairs the summary and the context once both arrived.
// They describe one state only when the context names the summary's policy
// set; otherwise the policy moved between the reads and both are read again.
func (m Model) settlePolicySnapshot() (tea.Model, tea.Cmd) {
	ctx := m.policies.loadedContext
	if m.policies.pendingPolicyID != "" || ctx == nil {
		return m, nil
	}
	if !ctx.Success || !m.policies.policy.Success {
		return m, nil
	}
	if ctx.PolicySetSHA256 != m.policies.policy.PolicySetSHA256 {
		return m.requestPolicy()
	}
	m.policies.snapshot = ctx.SnapshotSHA256
	return m, nil
}

func (m Model) handlePolicyLoaded(msg PolicyLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.Policy.ID == "" || msg.Policy.ID != m.policies.pendingPolicyID {
		return m, nil
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
			return m, m.sendGetPolicyDocumentCmd(key, "", m.policies.pendingDocumentID)
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
		return m, nil
	}
	m.policies.pendingDocumentID = ""
	m.policies.docLoading = false
	m.policies.document = msg.Document
	return m, nil
}

func (m Model) policyDocumentLines() []string {
	doc := m.policies.document
	if m.policies.docLoading || !doc.Success {
		return nil
	}
	// The node stores a file's exact bytes, so a policy written on Windows
	// has CRLF line ends, which are line ends here.
	lines := strings.Split(strings.TrimRight(doc.Document, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// policyDocumentKeys is the document view's footer without its scroll keys.
const policyDocumentKeys = "e: Edit | esc/q: Back"

func (m Model) policyDocumentVisibleLines() int {
	return m.pagerVisibleLines(m.policyDocumentHeader(m.policyDocumentWidth()), policyDocumentKeys+" | "+pagerScrollKeys)
}

func (m Model) handlePolicyDocumentKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewPolicies
		m.policies.scrollOffset = 0
		m.policies.pendingDocumentID = ""
		m.policies.docLoading = false
		return m, nil
	case "e":
		return m.openPolicyEditForDocument()
	}
	scrollPager(&m.policies.scrollOffset, msg.String(), len(m.policyDocumentLines()), m.policyDocumentVisibleLines())
	return m, nil
}

func (m Model) renderPolicies() string {
	var header strings.Builder
	header.WriteString(titleStyle.Render("Policies"))
	header.WriteString("\n")
	switch {
	case m.policies.loading:
		header.WriteString(subtitleStyle.Render("Loading policy..."))
		return header.String()
	case m.policies.err != "":
		header.WriteString(subtitleStyle.Render(wrapPlainText("Policy unavailable: "+terminalSafe(m.policies.err), m.tableWidth())))
		return header.String()
	}
	p := m.policies.policy
	header.WriteString(subtitleStyle.Render(fmt.Sprintf("%s node", p.NodeRole)))
	header.WriteString("\n\n")
	rows := m.policyRows()
	var lines []string
	if len(rows) == 0 {
		lines = append(lines, "No policy documents.")
	}
	labelWidth := m.policyLabelWidth(rows)
	for i, row := range rows {
		cursor := "  "
		if i == m.policies.selected {
			cursor = "> "
		}
		lines = append(lines, cursor+padRight(ellipsizeMiddle(terminalSafe(row.key), labelWidth), labelWidth)+"  "+policyRowStatus(row.key, row.status))
	}

	var footer strings.Builder
	footer.WriteString("\n")
	if m.policies.selected >= 0 && m.policies.selected < len(rows) {
		selected := rows[m.policies.selected]
		footer.WriteString(wrapPlainText(policyStatusLabel(selected.key, selected.status), m.tableWidth()) + "\n")
		if selected.doc != nil {
			footer.WriteString(policyDocumentMeta(*selected.doc) + "\n")
		}
		footer.WriteString("\n")
	}
	footer.WriteString(subtitleStyle.Render(wrapPlainText("policy_set_sha256 "+p.PolicySetSHA256, m.tableWidth())))
	footer.WriteString("\n")
	if m.policies.status != "" {
		footer.WriteString("\n")
		footer.WriteString(wrapPlainText(terminalSafeLines(m.policies.status), m.tableWidth()))
		footer.WriteString("\n")
	}
	fixed := strings.Count(header.String(), "\n") + strings.Count(footer.String(), "\n")
	return header.String() + m.listWindow(lines, m.policies.selected, fixed) + footer.String()
}

// policyStatusColumnWidth fits the longest policyRowStatus.
const policyStatusColumnWidth = 12

// policyLabelWidth sizes the list so an address, 58 characters, stays whole at
// MinWidth and statuses line up.
func (m Model) policyLabelWidth(rows []policyRow) int {
	const cursorAndGap = 2 + 2
	longest := 0
	for _, row := range rows {
		longest = max(longest, ansi.StringWidth(terminalSafe(row.key)))
	}
	return min(longest, max(m.tableWidth()-cursorAndGap-policyStatusColumnWidth, 8))
}

// policyRowStatus is the status on a list row; policyStatusLabel, shown below
// the list, is the same status in full.
func policyRowStatus(key, status string) string {
	switch {
	case key == policy.DefaultKey:
		return "node default"
	case status == adminproto.PolicyKeyOwn:
		return "own policy"
	case status == adminproto.PolicyKeyNotHeld:
		return "key not held"
	default:
		return "default"
	}
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

func (m Model) policyDocumentWidth() int {
	if m.width < 20 {
		return 80
	}
	return m.width
}

func policyDocumentTitle() string {
	return titleStyle.Render("Policy Document") + "\n"
}

// policyDocumentHeader is what the document view draws above the document.
func (m Model) policyDocumentHeader(width int) string {
	doc := m.policies.document
	return policyDocumentTitle() + subtitleStyle.Render(ellipsize(terminalSafe(doc.Key+"  sha256 "+doc.SHA256), width)) + "\n\n"
}

func (m Model) renderPolicyDocument() string {
	doc := m.policies.document
	switch {
	case m.policies.docLoading:
		return policyDocumentTitle() + subtitleStyle.Render("Loading document...")
	case !doc.Success:
		msg := doc.Error
		if msg == "" {
			msg = "document is unavailable"
		}
		return policyDocumentTitle() + subtitleStyle.Render("Document unavailable: "+terminalSafe(msg))
	}
	width := m.policyDocumentWidth()
	var sb strings.Builder
	sb.WriteString(m.policyDocumentHeader(width))
	writePagerLines(&sb, m.policyDocumentLines(), m.policies.scrollOffset, m.policyDocumentVisibleLines(), func(line string) string {
		// The stored bytes can hold control and bidirectional characters in
		// a string, which show as escapes.
		return ellipsize(terminalSafeLines(line), width)
	})
	return sb.String()
}

func (m Model) policiesFooterText() string {
	if m.viewState == ViewPolicyDocument {
		footer := policyDocumentKeys
		if len(m.policyDocumentLines()) > m.policyDocumentVisibleLines() {
			footer += " | " + pagerScrollKeys
		}
		return footer
	}
	return "up/down: Select | enter: View | e: Edit | a: Load file | x: Export | r: Refresh | esc/q: Back"
}

// sendGetPolicyCmd requests the node's policy summary under request id.
func (m Model) sendGetPolicyCmd(id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.sendMessage(protocol.GetPolicyMessage{BaseMessage: BaseMessage{Type: protocol.MsgTypeGetPolicy, ID: id}})
	})
}

// sendGetPolicyContextCmd requests the node's policy context under request id.
func (m Model) sendGetPolicyContextCmd(id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.sendMessage(protocol.GetPolicyContextMessage{BaseMessage: BaseMessage{Type: protocol.MsgTypeGetPolicyContext, ID: id}})
	})
}

// sendGetPolicyDocumentCmd requests one policy document under request id. A
// snapshot, when given, has the node refuse the read if its policy or context
// moved since then.
func (m Model) sendGetPolicyDocumentCmd(key, snapshot, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.sendMessage(protocol.GetPolicyDocumentMessage{
			BaseMessage:            BaseMessage{Type: protocol.MsgTypeGetPolicyDocument, ID: id},
			Key:                    key,
			ExpectedSnapshotSHA256: snapshot,
		})
	})
}
