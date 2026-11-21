// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/secretbuf"
	"github.com/aplane-algo/aplane/internal/witness"
)

// A cosigner key's Key Details shows the sources of the policy document that
// governs it, each with its token state, and opens a form that sets or
// removes a source's token. The tokens belong to the governing document's
// selector: the key's own document, or the node default the key follows.
// The typed token is held only in the form's buffer, which is zeroed on
// every way out of the form, and sent through secretCmd; no reply carries a
// token back.

// Source states as Key Details and the form show them.
const (
	sourceTokenSetLabel    = "token set"
	sourceTokenNeededLabel = "token needed"
	sourceNoTokenLabel     = "no token"
)

// sourceTokenRemovedNote follows a successful remove.
const sourceTokenRemovedNote = "Token removed. Earlier generations keep a copy until they are pruned; revoke the token at the service."

// sourceTokenRow is one source of the governing document.
type sourceTokenRow struct {
	name  string
	label string
	// hasToken is set when a token is stored for the source, whether or
	// not the document's source takes one.
	hasToken bool
}

// sourceTokensState is a cosigner key's sources and the token form.
type sourceTokensState struct {
	// key is the Witness Key ID the listing was asked for, and listID the
	// list request awaited.
	key    string
	listID string
	loaded bool
	// selector is the governing listing's selector: key, or "default".
	selector  string
	sources   []string
	rows      []sourceTokenRow
	listError string

	selected      int
	token         protocol.SensitiveBytes
	requestID     string
	pendingAction string // "set" or "remove" while a change is awaited
	status        string
	error         string
}

type sourceTokenListMsg protocol.SourceTokenListResultMessage
type sourceTokenChangeMsg protocol.SourceTokenChangeResultMessage

// clearSourceTokens zeroes a typed token and forgets the listing.
func (m *Model) clearSourceTokens() {
	m.sourceTokens.token.Zero()
	m.sourceTokens = sourceTokensState{}
}

// clearSourceTokenInput zeroes a typed token and keeps the listing.
func (m *Model) clearSourceTokenInput() {
	m.sourceTokens.token.Zero()
	m.sourceTokens.token = nil
}

// requestSourceTokens asks for the listing of the key Key Details shows,
// when it is a cosigner key on a cosigner node; otherwise it forgets any.
func (m *Model) requestSourceTokens() tea.Cmd {
	m.clearSourceTokens()
	if !m.isCosignerNode() || !witness.IsKeyType(m.details.keyType) {
		return nil
	}
	key, err := witness.NormalizeID(m.details.address)
	if err != nil {
		return nil
	}
	m.sourceTokens.key = key
	m.sourceTokens.listID = clockRequestID("source-tokens")
	return m.sendSourceTokenListCmd(key, m.sourceTokens.listID)
}

func (m Model) sendSourceTokenListCmd(selector, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.sendMessage(protocol.SourceTokenListMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenList, ID: id},
			Selector:    selector,
		})
	})
}

func (m Model) sendSourceTokenSetCmd(selector, source string, token []byte, id string) tea.Cmd {
	return secretCmd(token, func(p []byte) tea.Cmd {
		return operationCmd(m.adminClient, id, func(c *IPCClient) error {
			return c.sendMessage(protocol.SourceTokenSetMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenSet, ID: id},
				Selector:    selector, Source: source, Token: protocol.SensitiveBytes(p),
			})
		})
	})
}

func (m Model) sendSourceTokenRemoveCmd(selector, source, id string) tea.Cmd {
	return operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.sendMessage(protocol.SourceTokenRemoveMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenRemove, ID: id},
			Selector:    selector, Source: source,
		})
	})
}

// governingSourceTokens picks the listing whose tokens serve key's checks:
// key's own when it has a document of its own, the node default's when it
// follows that.
func governingSourceTokens(key string, listings []protocol.SourceTokenSelector) (protocol.SourceTokenSelector, bool) {
	var own, fallback *protocol.SourceTokenSelector
	for i := range listings {
		switch listings[i].Selector {
		case key:
			own = &listings[i]
		case "default":
			fallback = &listings[i]
		}
	}
	if own != nil && own.Policy == protocol.SourceTokenPolicyOwn {
		return *own, true
	}
	if fallback != nil {
		return *fallback, true
	}
	return protocol.SourceTokenSelector{}, false
}

// sourceTokenRows labels each source of the governing document from its
// token rows.
func sourceTokenRows(sources []string, tokens []protocol.SourceTokenInfo) []sourceTokenRow {
	rows := make([]sourceTokenRow, 0, len(sources))
	for _, name := range sources {
		row := sourceTokenRow{name: name, label: sourceNoTokenLabel}
		for _, token := range tokens {
			if token.Source != name {
				continue
			}
			switch token.State {
			case protocol.SourceTokenInUse:
				row.label, row.hasToken = sourceTokenSetLabel, true
			case protocol.SourceTokenNeeded:
				row.label = sourceTokenNeededLabel
			case protocol.SourceTokenUnused:
				row.hasToken = true
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func (m Model) handleSourceTokenList(msg sourceTokenListMsg) (tea.Model, tea.Cmd) {
	st := &m.sourceTokens
	if msg.ID == "" || msg.ID != st.listID {
		return m, nil
	}
	st.listID, st.loaded = "", true
	if !msg.Success {
		st.listError = terminalSafe(msg.Error)
		return m, nil
	}
	listing, ok := governingSourceTokens(st.key, msg.Selectors)
	if !ok {
		st.listError = ""
		st.selector, st.sources, st.rows = "", nil, nil
		return m, nil
	}
	st.listError = ""
	st.selector, st.sources = listing.Selector, listing.Sources
	st.rows = sourceTokenRows(listing.Sources, listing.Tokens)
	if st.selected >= len(st.rows) {
		st.selected = max(0, len(st.rows)-1)
	}
	return m, nil
}

func (m Model) handleSourceTokenChange(msg sourceTokenChangeMsg) (tea.Model, tea.Cmd) {
	st := &m.sourceTokens
	if st.pendingAction == "" || msg.ID != st.requestID {
		return m, nil
	}
	action := st.pendingAction
	st.pendingAction, st.requestID = "", ""
	if !msg.Success {
		st.error = terminalSafe(msg.Error)
		return m, nil
	}
	st.error = ""
	if msg.Selector == st.selector {
		st.rows = sourceTokenRows(st.sources, msg.Tokens)
	}
	if action == "remove" {
		st.status = sourceTokenRemovedNote
	} else {
		st.status = "Token set for " + terminalSafe(msg.Source) + "."
	}
	return m, nil
}

// failPendingSourceTokens fails the listing or the change id names.
func (m Model) failPendingSourceTokens(id string, err error) (Model, bool) {
	st := &m.sourceTokens
	switch {
	case id == "":
		return m, false
	case id == st.listID:
		st.listID, st.loaded, st.listError = "", true, terminalSafe(err.Error())
	case id == st.requestID && st.pendingAction != "":
		st.pendingAction, st.requestID, st.error = "", "", terminalSafe(err.Error())
	default:
		return m, false
	}
	return m, true
}

// openSourceTokens opens the token form for the sources Key Details shows.
func (m Model) openSourceTokens() (tea.Model, tea.Cmd) {
	if len(m.sourceTokens.rows) == 0 || m.signerState != signerRuntimeUnlocked {
		return m, nil
	}
	m.clearSourceTokenInput()
	st := &m.sourceTokens
	st.selected, st.status, st.error = 0, "", ""
	m.viewState = ViewSourceTokens
	return m, nil
}

func (m Model) handleSourceTokensKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	st := &m.sourceTokens
	if msg.Type == tea.KeyEsc {
		m.clearSourceTokenInput()
		st.status, st.error = "", ""
		m.viewState = ViewKeyDetails
		return m, nil
	}
	if st.pendingAction != "" {
		return m, nil
	}
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.moveSourceTokenSelection(-1)
	case tea.KeyDown, tea.KeyTab:
		m.moveSourceTokenSelection(1)
	case tea.KeyEnter:
		return m.submitSourceToken()
	case tea.KeyCtrlR:
		return m.removeSourceToken()
	case tea.KeyBackspace, tea.KeyCtrlH:
		st.token = secretbuf.TrimRune(st.token)
	case tea.KeyRunes:
		for _, r := range msg.Runes {
			st.token = secretbuf.AppendRune(st.token, r)
		}
	case tea.KeySpace:
		st.token = secretbuf.AppendRune(st.token, ' ')
	}
	return m, nil
}

// moveSourceTokenSelection selects another source and drops what was typed
// for the one before.
func (m *Model) moveSourceTokenSelection(delta int) {
	st := &m.sourceTokens
	if len(st.rows) == 0 {
		return
	}
	next := (st.selected + delta + len(st.rows)) % len(st.rows)
	if next != st.selected {
		m.clearSourceTokenInput()
		st.selected = next
	}
	st.status, st.error = "", ""
}

func (m Model) selectedSourceToken() (sourceTokenRow, bool) {
	st := m.sourceTokens
	if st.selected < 0 || st.selected >= len(st.rows) {
		return sourceTokenRow{}, false
	}
	return st.rows[st.selected], true
}

func (m Model) submitSourceToken() (tea.Model, tea.Cmd) {
	st := &m.sourceTokens
	row, ok := m.selectedSourceToken()
	if !ok {
		return m, nil
	}
	if len(st.token) == 0 {
		st.status, st.error = "", "Enter the token for "+terminalSafe(row.name)
		return m, nil
	}
	st.requestID = clockRequestID("source-token-set")
	st.pendingAction, st.status, st.error = "set", "", ""
	send := m.sendSourceTokenSetCmd(st.selector, row.name, st.token, st.requestID)
	m.clearSourceTokenInput()
	return m, send
}

func (m Model) removeSourceToken() (tea.Model, tea.Cmd) {
	st := &m.sourceTokens
	row, ok := m.selectedSourceToken()
	if !ok {
		return m, nil
	}
	m.clearSourceTokenInput()
	if !row.hasToken {
		st.status, st.error = "", "No token is set for "+terminalSafe(row.name)
		return m, nil
	}
	st.requestID = clockRequestID("source-token-remove")
	st.pendingAction, st.status, st.error = "remove", "", ""
	return m, m.sendSourceTokenRemoveCmd(st.selector, row.name, st.requestID)
}

// sourceTokensLine is Key Details' one line of sources, empty when the
// governing document has none.
func (m Model) sourceTokensLine() string {
	st := m.sourceTokens
	if !st.loaded {
		return ""
	}
	if st.listError != "" {
		return "Sources: " + st.listError
	}
	if len(st.rows) == 0 {
		return ""
	}
	parts := make([]string, 0, len(st.rows))
	for _, row := range st.rows {
		parts = append(parts, terminalSafe(row.name)+" "+row.label)
	}
	return "Sources: " + strings.Join(parts, ", ")
}

// sourceTokensPolicyLabel names the document whose tokens the form changes.
func (m Model) sourceTokensPolicyLabel() string {
	if m.sourceTokens.selector == "default" {
		return "node default"
	}
	return "this key's own"
}

// sourceTokensPopupWidth is the token form's popup width.
const sourceTokensPopupWidth = keyDetailsPopupWidth

func (m Model) renderSourceTokens() string {
	st := m.sourceTokens
	width := m.popupBodyWidth(sourceTokensPopupWidth)
	var b strings.Builder
	b.WriteString(titleStyle.Render("Source Tokens") + "\n")
	if st.key != "" {
		b.WriteString(ellipsizeMiddle(m.keyIdentifierLabel(m.details.keyType)+": "+st.key, width) + "\n")
		b.WriteString("Policy: " + m.sourceTokensPolicyLabel() + "\n")
	}
	b.WriteString("\n")
	nameWidth := 0
	for _, row := range st.rows {
		nameWidth = max(nameWidth, utf8.RuneCountInString(terminalSafe(row.name)))
	}
	nameWidth = min(nameWidth, max(1, width-4-len(sourceTokenNeededLabel)))
	for i, row := range st.rows {
		name := ellipsize(terminalSafe(row.name), nameWidth)
		line := fmt.Sprintf("  %-*s  %s", nameWidth, name, row.label)
		if i == st.selected {
			line = selectedStyle.Render(fmt.Sprintf("> %-*s  %s", nameWidth, name, row.label))
		}
		b.WriteString(line + "\n")
	}
	if len(st.rows) > 0 {
		b.WriteString("\n")
	}
	if st.pendingAction != "" {
		b.WriteString("Saving…\n")
	} else {
		b.WriteString("Token: " + strings.Repeat("*", utf8.RuneCount(st.token)) + "\n")
	}
	switch {
	case st.error != "":
		b.WriteString("\n" + errorStyle.Render(wrapText(st.error, width)) + "\n")
	case st.status != "":
		b.WriteString("\n" + wrapText(st.status, width) + "\n")
	}
	return m.renderPopup(sourceTokensPopupWidth, b.String())
}
