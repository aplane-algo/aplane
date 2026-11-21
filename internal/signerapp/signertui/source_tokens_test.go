// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/protocol"
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
	m.sourceTokens = sourceTokensState{key: sourceTokensTestKey, loaded: true, selector: "default",
		sources: []string{"ops", "screening", "treasury"},
		rows: []sourceTokenRow{
			{name: "ops", label: sourceNoTokenLabel},
			{name: "screening", label: sourceTokenSetLabel, hasToken: true},
			{name: "treasury", label: sourceTokenNeededLabel},
		}}
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
// node default uses the default's.
func TestGoverningSourceTokensListing(t *testing.T) {
	own := []protocol.SourceTokenSelector{{Selector: "K", Policy: protocol.SourceTokenPolicyOwn, Sources: []string{"a"}}}
	if got, ok := governingSourceTokens("K", own); !ok || got.Selector != "K" {
		t.Fatalf("own document: %+v, %v", got, ok)
	}
	follows := []protocol.SourceTokenSelector{
		{Selector: "K", Policy: protocol.SourceTokenPolicyDefault},
		{Selector: "default", Policy: protocol.SourceTokenPolicyOwn, Sources: []string{"b"}},
	}
	if got, ok := governingSourceTokens("K", follows); !ok || got.Selector != "default" {
		t.Fatalf("follows the default: %+v, %v", got, ok)
	}
	if _, ok := governingSourceTokens("K", nil); ok {
		t.Fatal("an empty reply has a governing listing")
	}
}

func TestKeyDetailsShowsTheGoverningDocumentsSources(t *testing.T) {
	m, id := sourceTokensDetailsModel(t)
	next, _ := m.Update(sourceTokensListing(id))
	m = next.(Model)
	if m.sourceTokens.selector != "default" {
		t.Fatalf("governing selector %q, want default", m.sourceTokens.selector)
	}
	want := "Sources: ops no token, screening token set, treasury token needed"
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
