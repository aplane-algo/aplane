// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/witness"
)

var sourceTokensTestKey = witness.DeriveID(witness.Falcon1024V1, []byte("source tokens test key"))

// sourceTokensListing is a cosigner key's reply: the key follows the node
// default, whose document names three sources.
func sourceTokensListing(id string) sourceTokenListMsg {
	return sourceTokenListMsg{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenListResult, ID: id},
		Success:     true,
		Selectors: []protocol.SourceTokenSelector{
			{Selector: sourceTokensTestKey, Policy: protocol.SourceTokenPolicyDefault, Tokens: []protocol.SourceTokenInfo{
				{Source: "stale", SetAt: "2026-11-20T00:00:00Z", State: protocol.SourceTokenUnused},
			}},
			{Selector: "default", Policy: protocol.SourceTokenPolicyOwn, Sources: []string{"ops", "screening", "treasury"}, Tokens: []protocol.SourceTokenInfo{
				{Source: "screening", SetAt: "2026-11-21T01:00:00Z", State: protocol.SourceTokenInUse},
				{Source: "treasury", State: protocol.SourceTokenNeeded},
			}},
		},
	}
}

// sourceTokensDetailsModel is Key Details for a cosigner key on a cosigner
// node, waiting for its sources.
func sourceTokensDetailsModel(t *testing.T) (Model, string) {
	t.Helper()
	m := activityReadyModel()
	m.initialNodeRole = "cosigner"
	// The details open only on the reply to the read the key list waits on.
	m.details.requestID = "details-1"
	next, cmd := m.Update(KeyDetailsMsg{ID: "details-1", Success: true, Address: sourceTokensTestKey, KeyType: witness.Falcon1024V1})
	m = next.(Model)
	if cmd == nil || m.sourceTokens.listID == "" || m.sourceTokens.key != sourceTokensTestKey {
		t.Fatalf("opening a cosigner key asked for no sources: %+v", m.sourceTokens)
	}
	return m, m.sourceTokens.listID
}

// sourceTokensFormModel is the token form open on the sources above.
func sourceTokensFormModel() Model {
	m := activityReadyModel()
	m.initialNodeRole = "cosigner"
	m.viewState = ViewSourceTokens
	m.details = keyDetailsState{address: sourceTokensTestKey, keyType: witness.Falcon1024V1}
	m.sourceTokens = sourceTokensState{key: sourceTokensTestKey, loaded: true,
		governing: protocol.SourceTokenSelector{Selector: "default", Policy: protocol.SourceTokenPolicyOwn,
			Sources: []string{"ops", "screening", "treasury"},
			Tokens: []protocol.SourceTokenInfo{
				{Source: "screening", SetAt: "2026-11-21T01:00:00Z", State: protocol.SourceTokenInUse},
				{Source: "treasury", State: protocol.SourceTokenNeeded},
			}}}
	m.sourceTokens.rows = sourceTokenRows(m.sourceTokens.governing, m.sourceTokens.leftover)
	return m
}

func TestSourceTokenResultsDecode(t *testing.T) {
	list, err := json.Marshal(sourceTokensListing("list-1"))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := signerMessageDecoders[protocol.MsgTypeSourceTokenListResult](list)
	if got, ok := msg.(sourceTokenListMsg); err != nil || !ok || got.ID != "list-1" || len(got.Selectors) != 2 || got.Selectors[1].Sources[1] != "screening" {
		t.Fatalf("list result decoded as %#v, %v", msg, err)
	}
	for _, msgType := range []string{protocol.MsgTypeSourceTokenSetResult, protocol.MsgTypeSourceTokenRemoveResult} {
		raw := []byte(`{"kind":"response","type":"` + msgType + `","id":"change-1","success":true,"selector":"default","source":"ops","tokens":[{"source":"ops","set_at":"2026-11-21T01:00:00Z","state":"in_use"}]}`)
		msg, err := signerMessageDecoders[msgType](raw)
		got, ok := msg.(sourceTokenChangeMsg)
		if err != nil || !ok || got.ID != "change-1" || got.Source != "ops" || len(got.Tokens) != 1 || got.Tokens[0].State != protocol.SourceTokenInUse {
			t.Fatalf("%s decoded as %#v, %v", msgType, msg, err)
		}
	}
}

// A key with a document of its own uses its own tokens; one that follows the
// node default uses the default's, and its own are left over.
func TestSourceTokenListings(t *testing.T) {
	own := protocol.SourceTokenSelector{Selector: "K", Policy: protocol.SourceTokenPolicyOwn, Sources: []string{"a"}}
	follows := protocol.SourceTokenSelector{Selector: "K", Policy: protocol.SourceTokenPolicyDefault}
	nodeDefault := protocol.SourceTokenSelector{Selector: "default", Policy: protocol.SourceTokenPolicyOwn, Sources: []string{"b"}}
	for _, tt := range []struct {
		name                string
		listings            []protocol.SourceTokenSelector
		governing, leftover string
	}{
		{"own document", []protocol.SourceTokenSelector{own}, "K", ""},
		{"own document, default listed too", []protocol.SourceTokenSelector{nodeDefault, own}, "K", ""},
		{"follows the default", []protocol.SourceTokenSelector{follows, nodeDefault}, "default", "K"},
		{"follows the default, not listed", []protocol.SourceTokenSelector{follows}, "", "K"},
		{"only the default listed", []protocol.SourceTokenSelector{nodeDefault}, "default", ""},
		{"another key's listing", []protocol.SourceTokenSelector{{Selector: "other", Policy: protocol.SourceTokenPolicyOwn}}, "", ""},
		{"empty reply", nil, "", ""},
	} {
		governing, leftover := sourceTokenListings("K", tt.listings)
		if governing.Selector != tt.governing || leftover.Selector != tt.leftover {
			t.Errorf("%s: governing %q, leftover %q, want %q, %q", tt.name, governing.Selector, leftover.Selector, tt.governing, tt.leftover)
		}
	}
}

func TestKeyDetailsShowsTheGoverningDocumentsSources(t *testing.T) {
	m, id := sourceTokensDetailsModel(t)
	next, _ := m.Update(sourceTokensListing(id))
	m = next.(Model)
	if m.sourceTokens.governing.Selector != "default" {
		t.Fatalf("governing selector %q, want default", m.sourceTokens.governing.Selector)
	}
	want := "Sources: ops no token, screening token set, treasury token needed, stale unused (key)"
	if got := m.sourceTokensLine(); got != want {
		t.Fatalf("sources line = %q, want %q", got, want)
	}
	if !strings.Contains(m.viewFooterText(), "o=source tokens") || !strings.Contains(m.keyDetailsTrailer(), "o: Source tokens") {
		t.Fatalf("Key Details does not offer the token form: %q", m.viewFooterText())
	}
	// A reply to an earlier request changes nothing.
	m.sourceTokens = sourceTokensState{key: sourceTokensTestKey, listID: "newer"}
	next, _ = m.Update(sourceTokensListing(id))
	if got := next.(Model).sourceTokensLine(); got != "" {
		t.Fatalf("a stale listing was shown: %q", got)
	}
}

func TestKeyDetailsAsksForSourcesOnlyForCosignerKeys(t *testing.T) {
	for _, tt := range []struct {
		name, role, keyType, address string
	}{
		{"signer node", "signer", witness.Falcon1024V1, sourceTokensTestKey},
		{"account key", "cosigner", "ed25519", "SGCU7MLRXQ4H227YCRTTT6MHL2N64WGJPHH3OTPID2CK4JNGJU6DITLIUQ"},
	} {
		m := activityReadyModel()
		m.initialNodeRole = tt.role
		m.details.requestID = "details-1"
		next, cmd := m.Update(KeyDetailsMsg{ID: "details-1", Success: true, Address: tt.address, KeyType: tt.keyType})
		m = next.(Model)
		if cmd != nil || m.sourceTokens.listID != "" || m.sourceTokensLine() != "" {
			t.Fatalf("%s: asked for sources", tt.name)
		}
		if next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}}); next.(Model).viewState != ViewKeyDetails {
			t.Fatalf("%s: o opened the token form", tt.name)
		}
	}
}

// A document with no sources shows no line and offers no form.
func TestKeyDetailsWithoutSourcesShowsNothing(t *testing.T) {
	m, id := sourceTokensDetailsModel(t)
	next, _ := m.Update(sourceTokenListMsg{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Selectors: []protocol.SourceTokenSelector{
		{Selector: sourceTokensTestKey, Policy: protocol.SourceTokenPolicyOwn},
	}})
	m = next.(Model)
	if m.sourceTokensLine() != "" || strings.Contains(m.viewFooterText(), "source tokens") {
		t.Fatalf("no sources, yet: %q / %q", m.sourceTokensLine(), m.viewFooterText())
	}
	if next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}}); next.(Model).viewState != ViewKeyDetails {
		t.Fatal("o opened the token form with no sources")
	}
}

func TestSourceTokenListFailureIsShown(t *testing.T) {
	m, id := sourceTokensDetailsModel(t)
	next, _ := m.Update(ErrorMsg{ID: id, Error: errString("authorization denied")})
	if got := next.(Model).sourceTokensLine(); got != "Sources: authorization denied" {
		t.Fatalf("sources line = %q", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestSourceTokenFormSetsTheSelectedSourcesToken(t *testing.T) {
	copies := watchSecretCopies(t)
	m := sourceTokensFormModel()
	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyDown},
		{Type: tea.KeyRunes, Runes: []rune("tok-12x")},
		{Type: tea.KeyBackspace},
		{Type: tea.KeyRunes, Runes: []rune("3")},
	} {
		next, _ := m.Update(key)
		m = next.(Model)
	}
	if got := string(m.sourceTokens.token); got != "tok-123" || m.sourceTokens.selected != 1 {
		t.Fatalf("typed %q on row %d", got, m.sourceTokens.selected)
	}
	if view := stripANSI(m.renderSourceTokens()); !strings.Contains(view, "Token: *******") || strings.Contains(view, "tok-123") {
		t.Fatalf("the token is not masked:\n%s", view)
	}
	typed := m.sourceTokens.token
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil || m.sourceTokens.pendingAction != "set" || m.sourceTokens.requestID == "" {
		t.Fatalf("Enter sent nothing: %+v", m.sourceTokens)
	}
	if len(m.sourceTokens.token) != 0 || !allZero(typed) {
		t.Fatalf("the typed token was kept after sending: %q", typed)
	}
	if len(*copies) != 1 || string((*copies)[0]) != "tok-123" {
		t.Fatalf("the send owns %q", *copies)
	}
	cmd()
	if !allZero((*copies)[0]) {
		t.Fatal("the send's copy was not zeroed")
	}

	// The reply relabels the sources from the selector's rows.
	reply := sourceTokenChangeMsg{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenSetResult, ID: m.sourceTokens.requestID},
		Success:     true, Selector: "default", Source: "screening",
		Tokens: []protocol.SourceTokenInfo{
			{Source: "ops", SetAt: "2026-11-21T02:00:00Z", State: protocol.SourceTokenUnused},
			{Source: "screening", SetAt: "2026-11-21T02:00:00Z", State: protocol.SourceTokenInUse},
			{Source: "treasury", State: protocol.SourceTokenNeeded},
		},
	}
	next, _ = m.Update(reply)
	m = next.(Model)
	if m.sourceTokens.pendingAction != "" || m.sourceTokens.status != "Token set for screening." {
		t.Fatalf("after the reply: %+v", m.sourceTokens)
	}
	if !m.sourceTokens.rows[0].hasToken || m.sourceTokens.rows[0].label != sourceNoTokenLabel {
		t.Fatalf("rows = %+v", m.sourceTokens.rows)
	}
	// A second copy of the reply is late, and changes nothing.
	m.sourceTokens.status = ""
	next, _ = m.Update(reply)
	if next.(Model).sourceTokens.status != "" {
		t.Fatal("a late reply was taken")
	}
}

func TestSourceTokenFormRemovesAndSaysRemovingDoesNotRevoke(t *testing.T) {
	m := sourceTokensFormModel()
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlR})
	m = next.(Model)
	if cmd != nil || m.sourceTokens.error != "No token is set for ops" {
		t.Fatalf("removing a token that is not set: %+v", m.sourceTokens)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(Model)
	next, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlR})
	m = next.(Model)
	if cmd == nil || m.sourceTokens.pendingAction != "remove" {
		t.Fatalf("ctrl+r sent nothing: %+v", m.sourceTokens)
	}
	if msg, ok := cmd().(sendFailedMsg); !ok || msg.ID != m.sourceTokens.requestID {
		t.Fatalf("remove command = %#v", msg)
	}
	next, _ = m.Update(sourceTokenChangeMsg{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenRemoveResult, ID: m.sourceTokens.requestID},
		Success:     true, Selector: "default", Source: "screening",
		Tokens: []protocol.SourceTokenInfo{{Source: "screening", State: protocol.SourceTokenNeeded}, {Source: "treasury", State: protocol.SourceTokenNeeded}},
	})
	m = next.(Model)
	if m.sourceTokens.status != sourceTokenRemovedNote || m.sourceTokens.rows[1].label != sourceTokenNeededLabel {
		t.Fatalf("after removing: %+v", m.sourceTokens)
	}
	if view := strings.Join(strings.Fields(stripANSI(m.renderSourceTokens())), " "); !strings.Contains(view, "revoke the token at the service") {
		t.Fatalf("the note is not shown:\n%s", view)
	}
}

func TestSourceTokenFormShowsTheServersRefusal(t *testing.T) {
	m := sourceTokensFormModel()
	m.sourceTokens.token = protocol.NewSensitiveBytes("tok")
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(sourceTokenChangeMsg{
		BaseMessage: protocol.BaseMessage{ID: m.sourceTokens.requestID},
		Code:        protocol.ErrCodeInvalidRequest, Error: "invalid source token: byte 2 is not visible ASCII\x1b[2J",
	})
	m = next.(Model)
	if m.sourceTokens.pendingAction != "" || strings.Contains(m.sourceTokens.error, "\x1b") || !strings.Contains(m.sourceTokens.error, "not visible ASCII") {
		t.Fatalf("refusal = %q", m.sourceTokens.error)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if got := next.(Model).sourceTokens.error; got != "Enter the token for ops" {
		t.Fatalf("Enter with nothing typed: %q", got)
	}
}

// Every way out of the form zeroes what was typed.
func TestSourceTokenFormZeroesTheTokenOnEveryExit(t *testing.T) {
	for _, event := range []tea.Msg{
		tea.KeyMsg{Type: tea.KeyEsc},
		tea.KeyMsg{Type: tea.KeyDown},
		tea.KeyMsg{Type: tea.KeyCtrlR},
		tea.KeyMsg{Type: tea.KeyCtrlC},
		SignerStatusMsg{State: "locked"},
		SignerStatusMsg{State: "recovery"},
		DisconnectedMsg{},
		ReconnectingMsg{},
	} {
		m := sourceTokensFormModel()
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("secret-token")})
		m = next.(Model)
		typed := m.sourceTokens.token
		next, _ = m.Update(event)
		if got := next.(Model).sourceTokens.token; len(got) != 0 || !allZero(typed) {
			t.Fatalf("%#v kept the token %q", event, typed)
		}
	}
	m := sourceTokensFormModel()
	m.sourceTokens.token = protocol.NewSensitiveBytes("secret-token")
	typed := m.sourceTokens.token
	m.Shutdown()
	if !allZero(typed) {
		t.Fatal("Shutdown kept the token")
	}
	if next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc}); next.(Model).viewState != ViewKeyDetails {
		t.Fatal("Esc does not return to Key Details")
	}
}

// Key Details with a full sources line and the token form fit the 80x24
// floor with everything on screen.
func TestSourceTokenViewsFitAtMinSize(t *testing.T) {
	sources := []string{"screening-primary", "treasury-allowances", "ops-switch", "sanctions-list"}
	details, id := sourceTokensDetailsModel(t)
	next, _ := details.Update(sourceTokenListMsg{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Selectors: []protocol.SourceTokenSelector{
		{Selector: sourceTokensTestKey, Policy: protocol.SourceTokenPolicyOwn, Sources: sources, Tokens: []protocol.SourceTokenInfo{
			{Source: "screening-primary", SetAt: "2026-11-21T01:00:00Z", State: protocol.SourceTokenInUse},
			{Source: "treasury-allowances", State: protocol.SourceTokenNeeded},
			{Source: "sanctions-list", State: protocol.SourceTokenNeeded},
		}},
	}})
	details = next.(Model)
	form := details
	form.viewState = ViewSourceTokens
	form.sourceTokens.token = protocol.NewSensitiveBytes("abcdef")
	form.sourceTokens.status = sourceTokenRemovedNote

	for _, tt := range []struct {
		name  string
		model Model
		want  []string
	}{
		{"key details", details, []string{"Sources: screening-primary token set, treasury-allowances token needed, ops-switch no token, sanctions-list token needed", "o: Source tokens"}},
		{"form", form, []string{"Source Tokens", "Policy: this key's own", "> screening-primary    token set", "treasury-allowances  token needed", "Token: ******", "revoke the token at the service"}},
	} {
		for _, standalone := range []bool{false, true} {
			tt.model.standalone = standalone
			m := sizedForTest(t, tt.model, MinWidth, MinHeight)
			view := stripANSI(m.View())
			lines := strings.Split(view, "\n")
			if len(lines) > MinHeight {
				t.Errorf("%s, standalone %v: %d lines in a %d-line window", tt.name, standalone, len(lines), MinHeight)
			}
			for _, line := range lines {
				if lipgloss.Width(line) > MinWidth {
					t.Errorf("%s, standalone %v: line wider than the window: %q", tt.name, standalone, line)
				}
			}
			flat := strings.Join(strings.Fields(strings.ReplaceAll(view, "║", " ")), " ")
			for _, want := range tt.want {
				if !strings.Contains(flat, strings.Join(strings.Fields(want), " ")) {
					t.Errorf("%s, standalone %v: %q missing from:\n%s", tt.name, standalone, want, view)
				}
			}
		}
	}
}

// sourceTokensWithUnused is the token form of a key that follows the node
// default, with a stored token the default has no source for, and the key's own
// leftovers, one of them by a name the default has too.
func sourceTokensWithUnused(t *testing.T) Model {
	t.Helper()
	m, id := sourceTokensDetailsModel(t)
	next, _ := m.Update(sourceTokenListMsg{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Selectors: []protocol.SourceTokenSelector{
		{Selector: sourceTokensTestKey, Policy: protocol.SourceTokenPolicyDefault, Tokens: []protocol.SourceTokenInfo{
			{Source: "screening", SetAt: "2026-11-19T00:00:00Z", State: protocol.SourceTokenUnused},
			{Source: "stale", SetAt: "2026-11-20T00:00:00Z", State: protocol.SourceTokenUnused},
		}},
		{Selector: "default", Policy: protocol.SourceTokenPolicyOwn, Sources: []string{"ops", "screening"}, Tokens: []protocol.SourceTokenInfo{
			{Source: "removed", SetAt: "2026-11-18T00:00:00Z", State: protocol.SourceTokenUnused},
			{Source: "screening", SetAt: "2026-11-21T01:00:00Z", State: protocol.SourceTokenInUse},
		}},
	}})
	m = next.(Model)
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	if m.viewState != ViewSourceTokens {
		t.Fatalf("the token form did not open: view %v", m.viewState)
	}
	return m
}

func sourceTokenRowText(m Model) string {
	var rows []string
	for _, row := range m.sourceTokens.rows {
		rows = append(rows, row.name+" "+row.label)
	}
	return strings.Join(rows, ", ")
}

// selectSourceToken moves the selection to row.
func selectSourceToken(t *testing.T, m Model, row int) Model {
	t.Helper()
	for range m.sourceTokens.rows {
		if m.sourceTokens.selected == row {
			return m
		}
		m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	t.Fatalf("no row %d among %q", row, sourceTokenRowText(m))
	return m
}

// A stored token no check uses is shown and can be removed: one of the governing
// document's selector that its document has no source for, and every one of a
// key that follows the node default, whatever the default calls its sources.
func TestUnusedSourceTokensAreShownAndRemovable(t *testing.T) {
	const all = "ops no token, screening token set, removed unused, screening unused (key), stale unused (key)"
	m := sourceTokensWithUnused(t)
	if got := sourceTokenRowText(m); got != all {
		t.Fatalf("rows = %q, want %q", got, all)
	}
	if got := m.sourceTokensLine(); got != "Sources: "+all {
		t.Fatalf("Key Details line = %q", got)
	}
	if m.sourceTokensPolicyLabel() != "node default" {
		t.Fatalf("policy = %q", m.sourceTokensPolicyLabel())
	}

	for _, tt := range []struct {
		row              int
		selector, source string
		tokens           []protocol.SourceTokenInfo // the selector's, after the remove
		left             string
	}{
		{2, "default", "removed", []protocol.SourceTokenInfo{{Source: "screening", State: protocol.SourceTokenInUse}},
			"ops no token, screening token set, screening unused (key), stale unused (key)"},
		{3, sourceTokensTestKey, "screening", []protocol.SourceTokenInfo{{Source: "stale", State: protocol.SourceTokenUnused}},
			"ops no token, screening token set, removed unused, stale unused (key)"},
		{4, sourceTokensTestKey, "stale", []protocol.SourceTokenInfo{{Source: "screening", State: protocol.SourceTokenUnused}},
			"ops no token, screening token set, removed unused, screening unused (key)"},
		{1, "default", "screening", []protocol.SourceTokenInfo{{Source: "removed", State: protocol.SourceTokenUnused}, {Source: "screening", State: protocol.SourceTokenNeeded}},
			"ops no token, screening token needed, removed unused, screening unused (key), stale unused (key)"},
	} {
		t.Run(tt.source+" of "+tt.selector, func(t *testing.T) {
			m := selectSourceToken(t, sourceTokensWithUnused(t), tt.row)
			client, written := wireClient(t)
			m.adminClient = client
			m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
			var sent protocol.SourceTokenRemoveMessage
			if err := json.Unmarshal([]byte(written(cmd)), &sent); err != nil || sent.Type != protocol.MsgTypeSourceTokenRemove {
				t.Fatalf("Ctrl+R sent %+v, %v", sent, err)
			}
			if sent.Selector != tt.selector || sent.Source != tt.source {
				t.Fatalf("remove names %s of %s, want %s of %s", sent.Source, sent.Selector, tt.source, tt.selector)
			}
			m, _ = updateForTest(t, m, sourceTokenChangeMsg{BaseMessage: protocol.BaseMessage{ID: m.sourceTokens.requestID},
				Success: true, Selector: tt.selector, Source: tt.source, Tokens: tt.tokens})
			if got := sourceTokenRowText(m); got != tt.left {
				t.Fatalf("rows after the remove = %q, want %q", got, tt.left)
			}
			if m.sourceTokens.status != sourceTokenRemovedNote {
				t.Fatalf("status %q", m.sourceTokens.status)
			}

			// A second Ctrl+R removes nothing: the selection is on the same
			// token, or on none once its row is gone.
			want := sourceTokenNoneSelected
			if row, ok := m.sourceTokens.selectedRow(); ok {
				if row.name != tt.source || row.selector != tt.selector {
					t.Fatalf("the selection moved to %s of %s", row.name, row.selector)
				}
				want = "No token is set for " + tt.source
			}
			m, cmd = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
			if cmd != nil || m.sourceTokens.pendingAction != "" || m.sourceTokens.error != want {
				t.Fatalf("a second Ctrl+R: action %q, error %q, want %q", m.sourceTokens.pendingAction, m.sourceTokens.error, want)
			}
		})
	}

	// A token set on the default keeps the key's leftovers.
	m = sourceTokensWithUnused(t)
	client, written := wireClient(t)
	m.adminClient = client
	m.sourceTokens.token = protocol.NewSensitiveBytes("tok")
	m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || m.sourceTokens.pendingAction != "set" {
		t.Fatalf("Enter on a source of the policy sent nothing: %+v", m.sourceTokens)
	}
	var set protocol.SourceTokenSetMessage
	if err := json.Unmarshal([]byte(written(cmd)), &set); err != nil || set.Selector != "default" || set.Source != "ops" {
		t.Fatalf("Enter sent a token for %s of %s, %v", set.Source, set.Selector, err)
	}
	m, _ = updateForTest(t, m, sourceTokenChangeMsg{BaseMessage: protocol.BaseMessage{ID: m.sourceTokens.requestID},
		Success: true, Selector: "default", Source: "ops", Tokens: []protocol.SourceTokenInfo{
			{Source: "ops", State: protocol.SourceTokenUnused},
			{Source: "removed", State: protocol.SourceTokenUnused},
			{Source: "screening", State: protocol.SourceTokenInUse},
		}})
	if got := sourceTokenRowText(m); got != all {
		t.Fatalf("rows after the set = %q, want %q", got, all)
	}
}

// Once the selected token is gone nothing is selected: Enter and Ctrl+R send and
// keep nothing, and the arrows start from either end of the list.
func TestRemovedSourceTokenLeavesNothingSelected(t *testing.T) {
	removed := func(t *testing.T) Model {
		m := selectSourceToken(t, sourceTokensWithUnused(t), 2)
		m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
		m, _ = updateForTest(t, m, sourceTokenChangeMsg{BaseMessage: protocol.BaseMessage{ID: m.sourceTokens.requestID},
			Success: true, Selector: "default", Source: "removed", Tokens: []protocol.SourceTokenInfo{{Source: "screening", State: protocol.SourceTokenInUse}}})
		if strings.Contains(stripANSI(m.renderSourceTokens()), "> ") {
			t.Fatalf("a row is marked as selected:\n%s", stripANSI(m.renderSourceTokens()))
		}
		return m
	}
	for _, key := range []tea.KeyType{tea.KeyEnter, tea.KeyCtrlR} {
		m, _ := updateForTest(t, removed(t), tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("typed-token")})
		typed := m.sourceTokens.token
		m, cmd := updateForTest(t, m, tea.KeyMsg{Type: key})
		if cmd != nil || m.sourceTokens.pendingAction != "" || m.sourceTokens.error != sourceTokenNoneSelected || m.sourceTokens.status != "" {
			t.Fatalf("%v: action %q, error %q, status %q", key, m.sourceTokens.pendingAction, m.sourceTokens.error, m.sourceTokens.status)
		}
		if len(m.sourceTokens.token) != 0 || !allZero(typed) {
			t.Fatalf("%v kept the typed token: %q", key, typed)
		}
	}
	for key, want := range map[tea.KeyType]int{tea.KeyDown: 0, tea.KeyUp: 3} {
		if m, _ := updateForTest(t, removed(t), tea.KeyMsg{Type: key}); m.sourceTokens.selected != want {
			t.Errorf("%v selects row %d, want %d", key, m.sourceTokens.selected, want)
		}
	}
	m, _ := updateForTest(t, removed(t), tea.KeyMsg{Type: tea.KeyEsc})
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	if m.viewState != ViewSourceTokens || m.sourceTokens.selected != 0 {
		t.Errorf("reopened on view %v, row %d", m.viewState, m.sourceTokens.selected)
	}
}

// A reply can hold another client's changes, and a newer policy's: the selection
// stays on its token, and only a token the signer calls unused is shown as one.
func TestSourceTokenReplyWithOtherChanges(t *testing.T) {
	m := selectSourceToken(t, sourceTokensWithUnused(t), 4)
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
	m, _ = updateForTest(t, m, sourceTokenChangeMsg{BaseMessage: protocol.BaseMessage{ID: m.sourceTokens.requestID},
		Success: true, Selector: sourceTokensTestKey, Source: "stale", Tokens: []protocol.SourceTokenInfo{
			{Source: "new-in-use", State: protocol.SourceTokenInUse},
			{Source: "new-needed", State: protocol.SourceTokenNeeded},
			{Source: "screening", State: protocol.SourceTokenInUse},
		}})
	if got, want := sourceTokenRowText(m), "ops no token, screening token set, removed unused"; got != want {
		t.Fatalf("rows = %q, want %q", got, want)
	}

	m = selectSourceToken(t, sourceTokensWithUnused(t), 1)
	m.sourceTokens.token = protocol.NewSensitiveBytes("tok")
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, _ = updateForTest(t, m, sourceTokenChangeMsg{BaseMessage: protocol.BaseMessage{ID: m.sourceTokens.requestID},
		Success: true, Selector: "default", Source: "screening", Tokens: []protocol.SourceTokenInfo{
			{Source: "new-needed", State: protocol.SourceTokenNeeded},
			{Source: "new-unused", State: protocol.SourceTokenUnused},
			{Source: "screening", State: protocol.SourceTokenInUse},
		}})
	if got, want := sourceTokenRowText(m), "ops no token, screening token set, new-unused unused, screening unused (key), stale unused (key)"; got != want {
		t.Fatalf("rows = %q, want %q", got, want)
	}
	if row, _ := m.sourceTokens.selectedRow(); row.name != "screening" || row.selector != "default" {
		t.Fatalf("the selection moved to %s of %s", row.name, row.selector)
	}

	// The selected token stays selected when one above it goes.
	m = selectSourceToken(t, sourceTokensWithUnused(t), 4)
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
	m, _ = updateForTest(t, m, sourceTokenChangeMsg{BaseMessage: protocol.BaseMessage{ID: m.sourceTokens.requestID},
		Success: true, Selector: sourceTokensTestKey, Source: "stale", Tokens: []protocol.SourceTokenInfo{{Source: "stale", State: protocol.SourceTokenUnused}}})
	if row, _ := m.sourceTokens.selectedRow(); row.name != "stale" || m.sourceTokens.selected != 3 {
		t.Fatalf("selected row %d, %q", m.sourceTokens.selected, row.name)
	}
}

// With the most tokens a form can show, the selected row, the token field and
// the answer stay on screen at the minimum size.
func TestEverySourceTokenFitsAtMinSize(t *testing.T) {
	governing := protocol.SourceTokenSelector{Selector: "default", Policy: protocol.SourceTokenPolicyOwn}
	leftover := protocol.SourceTokenSelector{Selector: sourceTokensTestKey, Policy: protocol.SourceTokenPolicyDefault}
	for i := range policy.MaxExternalSources {
		governing.Sources = append(governing.Sources, fmt.Sprintf("source-%d", i))
	}
	for i := range sourcetokens.MaxTokens {
		governing.Tokens = append(governing.Tokens, protocol.SourceTokenInfo{Source: fmt.Sprintf("removed-%d", i), State: protocol.SourceTokenUnused})
		leftover.Tokens = append(leftover.Tokens, protocol.SourceTokenInfo{Source: fmt.Sprintf("leftover-%d", i), State: protocol.SourceTokenUnused})
	}
	m, id := sourceTokensDetailsModel(t)
	m, _ = updateForTest(t, m, sourceTokenListMsg{BaseMessage: protocol.BaseMessage{ID: id}, Success: true,
		Selectors: []protocol.SourceTokenSelector{leftover, governing}})
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	rows := m.sourceTokens.rows
	if len(rows) != policy.MaxExternalSources+2*sourcetokens.MaxTokens {
		t.Fatalf("%d rows", len(rows))
	}
	for _, standalone := range []bool{false, true} {
		for i, row := range rows {
			m := selectSourceToken(t, m, i)
			m.standalone = standalone
			m.sourceTokens.status = sourceTokenRemovedNote
			m = sizedForTest(t, m, MinWidth, MinHeight)
			view := stripANSI(m.View())
			if strings.Contains(view, "Panel lines") {
				t.Fatalf("standalone %v, row %d: falls back to the panel scroller:\n%s", standalone, i, view)
			}
			for _, want := range []string{"> " + row.name + " ", "Token: ", "Token removed.", "token at the service."} {
				if !strings.Contains(view, want) {
					t.Fatalf("standalone %v, row %d: %q is off screen:\n%s", standalone, i, want, view)
				}
			}
		}
	}
}

// A token is set only for a source of the governing document.
func TestUnusedSourceTokensCannotBeSet(t *testing.T) {
	for _, row := range []int{2, 3, 4} {
		m := selectSourceToken(t, sourceTokensWithUnused(t), row)
		m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("typed-token")})
		typed := m.sourceTokens.token
		m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
		if cmd != nil || m.sourceTokens.pendingAction != "" {
			t.Fatalf("row %d: Enter sent a token: %+v", row, m.sourceTokens)
		}
		if m.sourceTokens.error != "No check uses this token. Press Ctrl+R to remove it." {
			t.Fatalf("row %d: error = %q", row, m.sourceTokens.error)
		}
		if len(m.sourceTokens.token) != 0 || !allZero(typed) {
			t.Fatalf("row %d: the typed token was kept: %q", row, typed)
		}
	}
}

// A key with a document of its own shows its own unused token as unused.
func TestUnusedSourceTokenOfAKeysOwnDocument(t *testing.T) {
	m, id := sourceTokensDetailsModel(t)
	next, _ := m.Update(sourceTokenListMsg{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Selectors: []protocol.SourceTokenSelector{
		{Selector: sourceTokensTestKey, Policy: protocol.SourceTokenPolicyOwn, Sources: []string{"screening"}, Tokens: []protocol.SourceTokenInfo{
			{Source: "removed", State: protocol.SourceTokenUnused},
			{Source: "screening", State: protocol.SourceTokenInUse},
		}},
	}})
	m = next.(Model)
	if got := sourceTokenRowText(m); got != "screening token set, removed unused" || m.sourceTokensPolicyLabel() != "this key's own" {
		t.Fatalf("rows = %q, policy %q", got, m.sourceTokensPolicyLabel())
	}
}

// A key with nothing but leftovers still offers the form, and removing the last
// of them leaves it empty.
func TestRemovingTheOnlyUnusedSourceToken(t *testing.T) {
	m, id := sourceTokensDetailsModel(t)
	next, _ := m.Update(sourceTokenListMsg{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Selectors: []protocol.SourceTokenSelector{
		{Selector: sourceTokensTestKey, Policy: protocol.SourceTokenPolicyDefault, Tokens: []protocol.SourceTokenInfo{{Source: "stale", State: protocol.SourceTokenUnused}}},
		{Selector: "default", Policy: protocol.SourceTokenPolicyOwn},
	}})
	m = next.(Model)
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
	m, _ = updateForTest(t, m, sourceTokenChangeMsg{BaseMessage: protocol.BaseMessage{ID: m.sourceTokens.requestID},
		Success: true, Selector: sourceTokensTestKey, Source: "stale"})
	if len(m.sourceTokens.rows) != 0 || m.sourceTokens.status != sourceTokenRemovedNote {
		t.Fatalf("after removing the only row: %+v", m.sourceTokens)
	}
	for _, key := range []tea.KeyMsg{{Type: tea.KeyDown}, {Type: tea.KeyUp}, {Type: tea.KeyEnter}, {Type: tea.KeyCtrlR}} {
		var cmd tea.Cmd
		if m, cmd = updateForTest(t, m, key); cmd != nil {
			t.Fatalf("%v sent something with no rows", key)
		}
	}
	_ = m.renderSourceTokens()
	if m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEsc}); m.viewState != ViewKeyDetails || m.sourceTokensLine() != "" {
		t.Fatalf("view %v, line %q", m.viewState, m.sourceTokensLine())
	}
}

// The longest source name keeps each label on its row at the 80-column floor.
func TestUnusedSourceTokenLabelsFitOneRow(t *testing.T) {
	long := strings.Repeat("n", 64)
	m, id := sourceTokensDetailsModel(t)
	next, _ := m.Update(sourceTokenListMsg{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Selectors: []protocol.SourceTokenSelector{
		{Selector: sourceTokensTestKey, Policy: protocol.SourceTokenPolicyDefault, Tokens: []protocol.SourceTokenInfo{{Source: long, State: protocol.SourceTokenUnused}}},
		{Selector: "default", Policy: protocol.SourceTokenPolicyOwn, Sources: []string{long}, Tokens: []protocol.SourceTokenInfo{
			{Source: long, State: protocol.SourceTokenNeeded},
			{Source: strings.Repeat("r", 64), State: protocol.SourceTokenUnused},
		}},
	}})
	m = next.(Model)
	m.viewState = ViewSourceTokens
	m = sizedForTest(t, m, MinWidth, MinHeight)
	view := stripANSI(m.View())
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > MinWidth {
			t.Errorf("line wider than the window: %q", line)
		}
	}
	for _, label := range []string{sourceTokenNeededLabel, sourceTokenUnusedLabel, sourceTokenUnusedKeyLabel} {
		found := false
		for _, line := range strings.Split(view, "\n") {
			text := strings.Trim(line, " ║│")
			if (strings.Contains(text, "nnn") || strings.Contains(text, "rrr")) && strings.HasSuffix(text, "  "+label) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not on its source's row:\n%s", label, view)
		}
	}
}
