// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// The policies view lists the node's active policy documents read-only.
// Changes go through apadmin policy check and apply, never through the TUI.

// policiesState is the read-only policy list and document viewer.
type policiesState struct {
	loading      bool
	err          string
	policy       protocol.PolicyMessage
	selected     int
	scrollOffset int
	returnView   ViewState
}

// PolicyLoadedMsg carries the daemon's policy response.
type PolicyLoadedMsg struct {
	Policy protocol.PolicyMessage
}

// policyRow is one line of the policies list.
type policyRow struct {
	label  string
	status string
	doc    *protocol.PolicyDocumentWire
}

func (m Model) openPolicies() (tea.Model, tea.Cmd) {
	m.policies = policiesState{loading: true, returnView: m.viewState}
	m.viewState = ViewPolicies
	return m, tea.Batch(m.sendGetPolicyCmd(), m.waitForMessageCmd())
}

func (m Model) handlePolicyLoaded(msg PolicyLoadedMsg) (tea.Model, tea.Cmd) {
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
	return m, m.waitForMessageCmd()
}

func (m Model) policyRows() []policyRow {
	p := m.policies.policy
	byKey := make(map[string]*protocol.PolicyDocumentWire, len(p.Documents))
	for i := range p.Documents {
		byKey[p.Documents[i].Key] = &p.Documents[i]
	}
	if p.NodeRole == "signer" {
		if doc := byKey[""]; doc != nil {
			return []policyRow{{label: "policy.json", status: "active", doc: doc}}
		}
		return nil
	}
	rows := make([]policyRow, 0, len(p.Keys))
	for _, key := range p.Keys {
		rows = append(rows, policyRow{label: key.Key, status: key.Status, doc: byKey[key.Key]})
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
		return m.openPoliciesRefresh()
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
			m.viewState = ViewPolicyDocument
		}
	}
	return m, nil
}

func (m Model) openPoliciesRefresh() (tea.Model, tea.Cmd) {
	m.policies.loading = true
	return m, tea.Batch(m.sendGetPolicyCmd(), m.waitForMessageCmd())
}

func (m Model) selectedPolicyDocument() *protocol.PolicyDocumentWire {
	rows := m.policyRows()
	if m.policies.selected < len(rows) {
		return rows[m.policies.selected].doc
	}
	return nil
}

func (m Model) policyDocumentLines() []string {
	doc := m.selectedPolicyDocument()
	if doc == nil {
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
	sb.WriteString(subtitleStyle.Render(fmt.Sprintf("%s node  ·  read-only; change with apadmin policy check / apply", p.NodeRole)))
	sb.WriteString("\n\n")
	rows := m.policyRows()
	if len(rows) == 0 {
		sb.WriteString("No cosigner keys and no policy documents.\n")
	}
	for i, row := range rows {
		cursor := "  "
		if i == m.policies.selected {
			cursor = "> "
		}
		sb.WriteString(cursor + row.label + "  " + policyStatusLabel(row.status))
		if row.doc != nil {
			sb.WriteString("  " + policyDocumentMeta(*row.doc))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("policy_set_sha256 " + p.PolicySetSHA256))
	sb.WriteString("\n")
	return sb.String()
}

func policyStatusLabel(status string) string {
	switch status {
	case "no_policy":
		return "no policy (rejects every request)"
	case "key_not_held":
		return "policy, key not held"
	default:
		return "active"
	}
}

func policyDocumentMeta(doc protocol.PolicyDocumentWire) string {
	meta := fmt.Sprintf("%d bytes  sha256 %s", len(doc.Document), shortDigest(doc.SHA256))
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
	doc := m.selectedPolicyDocument()
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Policy Document"))
	sb.WriteString("\n")
	if doc == nil {
		return sb.String()
	}
	label := "policy.json"
	if doc.Key != "" {
		label = doc.Key
	}
	sb.WriteString(subtitleStyle.Render(ellipsize(label+"  sha256 "+doc.SHA256, width)))
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
		footer := "esc/q: Back"
		if len(m.policyDocumentLines()) > m.policyDocumentVisibleLines() {
			footer += " | up/down/pgup/pgdown: Scroll"
		}
		return footer
	}
	return "up/down: Select | enter: View | r: Refresh | esc/q: Back"
}

// SendGetPolicy requests the node's policy documents.
func (c *IPCClient) SendGetPolicy() error {
	return c.sendMessage(protocol.GetPolicyMessage{
		BaseMessage: BaseMessage{Type: protocol.MsgTypeGetPolicy, ID: fmt.Sprintf("policy-%d", time.Now().UnixNano())},
	})
}

func (m Model) sendGetPolicyCmd() tea.Cmd {
	return ipcCmd(m.adminClient, func(c *IPCClient) error { return c.SendGetPolicy() })
}
