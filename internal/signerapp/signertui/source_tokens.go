// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"slices"
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
// selector: the key's own document, or the node default the key follows. Stored
// tokens that belong to none of the sources are shown after them and can be
// removed.
// The typed token is held only in the form's buffer, which is zeroed on
// every way out of the form, and sent through secretCmd; no reply carries a
// token back.

// Source states as Key Details and the form show them.
const (
	sourceTokenSetLabel    = "token set"
	sourceTokenNeededLabel = "token needed"
	sourceNoTokenLabel     = "no token"
	// sourceTokenUnusedLabel is a stored token the governing document has no
	// source for, and sourceTokenUnusedKeyLabel one stored under a key that
	// follows the node default.
	sourceTokenUnusedLabel    = "unused"
	sourceTokenUnusedKeyLabel = "unused (key)"
)

// sourceTokenRemovedNote follows a successful remove.
const sourceTokenRemovedNote = "Token removed. Earlier generations and backups keep a copy; revoke the token at the service."

// sourceTokenNoneSelected answers Enter and Ctrl+R while no row is selected.
const sourceTokenNoneSelected = "No source is selected."

// sourceTokenRow is one source of the governing document, or a stored token no
// source of it names.
type sourceTokenRow struct {
	name  string
	label string
	// selector is whose token the row is, the one a set or remove names.
	selector string
	// declared is set for a source of the governing document. A token is set
	// only for one of those; any other can only be removed.
	declared bool
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
	// governing is the listing whose tokens serve the key's checks, and
	// leftover the key's own when that isn't it (see sourceTokenListings).
	governing protocol.SourceTokenSelector
	leftover  protocol.SourceTokenSelector
	rows      []sourceTokenRow
	listError string

	// selected is the selected row, or -1 for none (see refreshRows).
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

// sourceTokenListings picks the listing whose tokens serve key's checks: key's
// own when it has a document of its own, the node default's when it follows
// that. Then leftover is key's own listing, whose tokens serve nothing.
func sourceTokenListings(key string, listings []protocol.SourceTokenSelector) (governing, leftover protocol.SourceTokenSelector) {
	for _, listing := range listings {
		switch listing.Selector {
		case key:
			leftover = listing
		case "default":
			governing = listing
		}
	}
	if leftover.Policy == protocol.SourceTokenPolicyOwn {
		return leftover, protocol.SourceTokenSelector{}
	}
	return governing, leftover
}

// sourceTokenRows is each source of the governing document, labelled from its
// token rows, then the stored tokens that belong to none of them: those the
// document has no source for, and the leftover listing's. A change's reply is
// newer than the listing's sources, so only a token the signer calls unused is
// one.
func sourceTokenRows(governing, leftover protocol.SourceTokenSelector) []sourceTokenRow {
	rows := make([]sourceTokenRow, 0, len(governing.Sources))
	for _, name := range governing.Sources {
		row := sourceTokenRow{name: name, label: sourceNoTokenLabel, selector: governing.Selector, declared: true}
		for _, token := range governing.Tokens {
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
	for _, token := range governing.Tokens {
		if token.State == protocol.SourceTokenUnused && !slices.Contains(governing.Sources, token.Source) {
			rows = append(rows, sourceTokenRow{name: token.Source, label: sourceTokenUnusedLabel, selector: governing.Selector, hasToken: true})
		}
	}
	for _, token := range leftover.Tokens {
		if token.State == protocol.SourceTokenUnused {
			rows = append(rows, sourceTokenRow{name: token.Source, label: sourceTokenUnusedKeyLabel, selector: leftover.Selector, hasToken: true})
		}
	}
	return rows
}

// refreshRows rebuilds the rows after a change. The selection stays on the
// token it was on, and is on none once that token is gone: were it on the row
// that took its place, a second Ctrl+R would remove a token nobody chose.
func (st *sourceTokensState) refreshRows() {
	was, _ := st.selectedRow()
	st.rows = sourceTokenRows(st.governing, st.leftover)
	st.selected = slices.IndexFunc(st.rows, func(row sourceTokenRow) bool {
		return row.selector == was.selector && row.name == was.name
	})
}

func (st *sourceTokensState) selectedRow() (sourceTokenRow, bool) {
	if st.selected < 0 || st.selected >= len(st.rows) {
		return sourceTokenRow{}, false
	}
	return st.rows[st.selected], true
}

// routeSourceTokenList hands a token listing to the policy export waiting on
// it, or else to the key's source tokens view.
func (m Model) routeSourceTokenList(msg sourceTokenListMsg) (tea.Model, tea.Cmd) {
	if next, cmd, ok := m.handlePolicyExportSourceTokens(msg); ok {
		return next, cmd
	}
	return m.handleSourceTokenList(msg)
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
	st.listError = ""
	st.governing, st.leftover = sourceTokenListings(st.key, msg.Selectors)
	st.rows = sourceTokenRows(st.governing, st.leftover)
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
	switch msg.Selector {
	case st.governing.Selector:
		st.governing.Tokens = msg.Tokens
	case st.leftover.Selector:
		st.leftover.Tokens = msg.Tokens
	}
	st.refreshRows()
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
	from := st.selected
	if from < 0 && delta < 0 {
		from = 0 // up from no selection is the last row, as down is the first
	}
	next := (from + delta + len(st.rows)) % len(st.rows)
	if next != st.selected {
		m.clearSourceTokenInput()
		st.selected = next
	}
	st.status, st.error = "", ""
}

func (m Model) submitSourceToken() (tea.Model, tea.Cmd) {
	st := &m.sourceTokens
	row, ok := st.selectedRow()
	if !ok {
		m.clearSourceTokenInput()
		st.status, st.error = "", sourceTokenNoneSelected
		return m, nil
	}
	if !row.declared {
		m.clearSourceTokenInput()
		st.status, st.error = "", "No check uses this token. Press Ctrl+R to remove it."
		return m, nil
	}
	if len(st.token) == 0 {
		st.status, st.error = "", "Enter the token for "+terminalSafe(row.name)
		return m, nil
	}
	st.requestID = clockRequestID("source-token-set")
	st.pendingAction, st.status, st.error = "set", "", ""
	send := m.sendSourceTokenSetCmd(row.selector, row.name, st.token, st.requestID)
	m.clearSourceTokenInput()
	return m, send
}

func (m Model) removeSourceToken() (tea.Model, tea.Cmd) {
	st := &m.sourceTokens
	m.clearSourceTokenInput()
	row, ok := st.selectedRow()
	if !ok {
		st.status, st.error = "", sourceTokenNoneSelected
		return m, nil
	}
	if !row.hasToken {
		st.status, st.error = "", "No token is set for "+terminalSafe(row.name)
		return m, nil
	}
	st.requestID = clockRequestID("source-token-remove")
	st.pendingAction, st.status, st.error = "remove", "", ""
	return m, m.sendSourceTokenRemoveCmd(row.selector, row.name, st.requestID)
}

// sourceTokensLine is Key Details' one line of sources, empty when the
// governing document has none and no unused token is stored.
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
	if m.sourceTokens.governing.Selector == m.sourceTokens.key {
		return "this key's own"
	}
	return "node default"
}

// sourceTokensPopupWidth is the token form's popup width.
const sourceTokensPopupWidth = keyDetailsPopupWidth

func (m Model) renderSourceTokens() string {
	st := m.sourceTokens
	width := m.popupBodyWidth(sourceTokensPopupWidth)
	var header, footer strings.Builder
	header.WriteString(titleStyle.Render("Source Tokens") + "\n")
	if st.key != "" {
		header.WriteString(ellipsizeMiddle(m.keyIdentifierLabel(m.details.keyType)+": "+st.key, width) + "\n")
		header.WriteString("Policy: " + m.sourceTokensPolicyLabel() + "\n")
	}
	header.WriteString("\n")
	nameWidth := 0
	for _, row := range st.rows {
		nameWidth = max(nameWidth, utf8.RuneCountInString(terminalSafe(row.name)))
	}
	nameWidth = min(nameWidth, max(1, width-4-len(sourceTokenNeededLabel)))
	lines := make([]string, len(st.rows))
	for i, row := range st.rows {
		name := ellipsize(terminalSafe(row.name), nameWidth)
		lines[i] = fmt.Sprintf("  %-*s  %s", nameWidth, name, row.label)
		if i == st.selected {
			lines[i] = selectedStyle.Render(fmt.Sprintf("> %-*s  %s", nameWidth, name, row.label))
		}
	}
	if len(st.rows) > 0 {
		footer.WriteString("\n")
	}
	if st.pendingAction != "" {
		footer.WriteString("Saving…\n")
	} else {
		footer.WriteString("Token: " + strings.Repeat("*", utf8.RuneCount(st.token)) + "\n")
	}
	switch {
	case st.error != "":
		footer.WriteString("\n" + errorStyle.Render(wrapText(st.error, width)) + "\n")
	case st.status != "":
		footer.WriteString("\n" + wrapText(st.status, width) + "\n")
	}
	body := m.fitSelectionList(header.String(), lines, st.selected, footer.String(), sourceTokensPopupWidth)
	return m.renderPopup(sourceTokensPopupWidth, body)
}
