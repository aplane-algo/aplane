// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
)

func TestBuildDetailsParameterLinesFormatsAddressList(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "whitelist-test-v1",
		DisplayName: "Whitelist Test",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:  "recipients",
			Label: "Recipients",
			Type:  "address[]",
		}},
	}})

	got := buildDetailsParameterLines("whitelist-test-v1", map[string]string{
		"recipients": "ADDR1,ADDR2,ADDR3",
	})
	want := []string{"Recipients:", "  ADDR1", "  ADDR2", "  ADDR3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildDetailsParameterLines() = %#v, want %#v", got, want)
	}
}

func TestBuildDetailsParameterLinesGuardedShowsSentrySelector(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     keytypes.GuardedFalcon1024SentryEd25519V1,
		DisplayName: "Falcon Sentry",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:  keytypes.ParameterSentryPublicKey,
			Label: "Sentry public key",
			Type:  "bytes",
		}},
	}})

	got := buildDetailsParameterLines(keytypes.GuardedFalcon1024SentryEd25519V1, map[string]string{
		"Sentry":                          "75OU3CR55IDLKDFEZSFWLIRGE2I5Q337D3NTKAEHJ6K7FGYON5AA",
		keytypes.ParameterSentryPublicKey: "aabbccdd",
	})
	want := []string{"Sentry: 75OU3CR55IDLKDFEZSFWLIRGE2I5Q337D3NTKAEHJ6K7FGYON5AA"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildDetailsParameterLines(guarded) = %#v, want %#v", got, want)
	}
}

func TestRenderKeyDetailsShowsAddressListOnePerLine(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "whitelist-test-v1",
		DisplayName: "Whitelist Test",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:  "recipients",
			Label: "Recipients",
			Type:  "address[]",
		}},
	}})

	rendered := Model{details: keyDetailsState{keyType: "whitelist-test-v1", parameters: map[string]string{
		"recipients": "ADDR1,ADDR2",
	}}, height: 30,
	}.renderKeyDetails()

	if strings.Contains(rendered, "ADDR1,ADDR2") ||
		!strings.Contains(rendered, "Recipients:") ||
		!strings.Contains(rendered, "ADDR1") ||
		!strings.Contains(rendered, "ADDR2") {
		t.Fatalf("renderKeyDetails() did not display address list as separate entries:\n%s", rendered)
	}
}

func TestRenderKeyListMiddleEllipsizesLongAddresses(t *testing.T) {
	const address = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	const shortened = "ABCDEFGHIJ...WXYZ234567"
	m := Model{
		width:  120,
		height: 20,
		keylist: keyListState{keys: []KeyInfo{{
			Address: address,
			KeyType: "ed25519",
		}}},
	}

	rendered := m.renderKeyListView()
	clean := stripANSI(rendered)
	if strings.Contains(clean, address) {
		t.Fatalf("renderKeyListView() rendered full address in narrow view:\n%s", clean)
	}
	if !strings.Contains(clean, "...") {
		t.Fatalf("renderKeyListView() did not middle-ellipsize long address:\n%s", clean)
	}
	if !strings.Contains(clean, shortened) {
		t.Fatalf("renderKeyListView() missing standard shortened address %q:\n%s", shortened, clean)
	}

	for _, line := range strings.Split(rendered, "\n") {
		if !strings.Contains(stripANSI(line), "[ed25519]") {
			continue
		}
		if width := visibleWidth(line); width > m.width {
			t.Fatalf("key list line width = %d, want <= %d\nline: %q\nview:\n%s", width, m.width, stripANSI(line), clean)
		}
	}
}

func TestRenderKeyListViewShowsTemplateConflictStatus(t *testing.T) {
	m := Model{
		width:  120,
		height: 20,
		keylist: keyListState{keys: []KeyInfo{{
			Address:                  "ADDR",
			KeyType:                  "mytemplate-v1",
			TemplateProvenanceStatus: "conflict",
		}}},
	}

	rendered := stripANSI(m.renderKeyListView())
	if !strings.Contains(rendered, "[mytemplate-v1] [template mismatch]") {
		t.Fatalf("renderKeyListView() missing template mismatch status:\n%s", rendered)
	}
}

func TestRenderKeyListViewUsesSignerNodeWithoutTabs(t *testing.T) {
	m := Model{
		width:  120,
		height: 24,
		admin:  adminPanelState{settings: &AdminSettings{NodeRole: "signer"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "SENTRYKEY", KeyType: keytypes.SentryComponentEd25519V1},
		}},
	}

	rendered := stripANSI(m.renderKeyListView())
	if strings.Contains(rendered, "Signing (1)") || strings.Contains(rendered, "Sentry (1)") {
		t.Fatalf("signer node rendered tab controls:\n%s", rendered)
	}
	if !strings.Contains(rendered, "SIGNINGADDR") {
		t.Fatalf("signer node missing signing key:\n%s", rendered)
	}
	if strings.Contains(rendered, "SENTRYKEY") {
		t.Fatalf("signer node showed sentry key:\n%s", rendered)
	}
}

func TestRenderKeyListViewDefaultsToSignerNodeWithoutTabs(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		width:     120,
		height:    24,
		admin:     adminPanelState{settings: &AdminSettings{}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "SENTRYKEY", KeyType: keytypes.SentryComponentEd25519V1},
		}},
	}

	rendered := stripANSI(m.renderKeyListView())
	if strings.Contains(rendered, "Signing (1)") || strings.Contains(rendered, "Sentry (1)") {
		t.Fatalf("signing mode rendered tab controls:\n%s", rendered)
	}
	if !strings.Contains(rendered, "SIGNINGADDR") {
		t.Fatalf("signing mode missing signing key:\n%s", rendered)
	}
	if strings.Contains(rendered, "SENTRYKEY") {
		t.Fatalf("signing mode showed sentry key:\n%s", rendered)
	}
	if strings.Contains(m.viewFooterText(), "Switch tab") {
		t.Fatalf("signing mode footer advertised tab switching: %q", m.viewFooterText())
	}
}

func TestRenderKeyListViewUsesSentryNodeWithoutTabs(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		width:     120,
		height:    24,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "sentry"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "SENTRYKEY", KeyType: keytypes.SentryComponentEd25519V1},
		}},
	}

	rendered := stripANSI(m.renderKeyListView())
	if strings.Contains(rendered, "Signing (1)") || strings.Contains(rendered, "Sentry (1)") {
		t.Fatalf("sentry node rendered tab controls:\n%s", rendered)
	}
	if !strings.Contains(rendered, "SENTRYKEY") {
		t.Fatalf("sentry node missing sentry key:\n%s", rendered)
	}
	if strings.Contains(rendered, "SIGNINGADDR") {
		t.Fatalf("sentry node showed signing key:\n%s", rendered)
	}
	if strings.Contains(m.viewFooterText(), "Switch tab") {
		t.Fatalf("sentry node footer advertised tab switching: %q", m.viewFooterText())
	}
}

func TestHandleKeyListKeysIgnoresTabOnSentryNode(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "sentry"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "SENTRYKEY", KeyType: keytypes.SentryComponentEd25519V1},
		}},
	}

	nextModel, _ := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyTab})
	next := nextModel.(Model)
	if next.effectiveKeyListTab() != keyListTabSentry {
		t.Fatalf("effectiveKeyListTab after tab = %v, want sentry", next.effectiveKeyListTab())
	}
	keys := next.filteredKeys()
	if len(keys) != 1 || keys[0].Address != "SENTRYKEY" {
		t.Fatalf("sentry filtered keys = %#v, want sentry key", keys)
	}
}

func TestHandleKeyListKeysIgnoresTabsOnSignerNode(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "signer"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "SENTRYKEY", KeyType: keytypes.SentryComponentEd25519V1},
		}},
	}

	nextModel, _ := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyTab})
	next := nextModel.(Model)
	if next.effectiveKeyListTab() != keyListTabSigning {
		t.Fatalf("effectiveKeyListTab after tab = %v, want signing", next.effectiveKeyListTab())
	}
	keys := next.filteredKeys()
	if len(keys) != 1 || keys[0].Address != "SIGNINGADDR" {
		t.Fatalf("signing filtered keys = %#v, want signing key", keys)
	}
}

func TestSelectKeyByAddressSwitchesToSentryTab(t *testing.T) {
	m := Model{admin: adminPanelState{settings: &AdminSettings{NodeRole: "sentry"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "SENTRYKEY", KeyType: keytypes.SentryComponentEd25519V1},
		}},
	}

	m.selectKeyByAddress("SENTRYKEY")
	if m.keylist.tab != keyListTabSentry {
		t.Fatalf("keyListTab = %v, want sentry", m.keylist.tab)
	}
	if m.keylist.selectedKey != 0 {
		t.Fatalf("selectedKey = %d, want first sentry tab row", m.keylist.selectedKey)
	}
}

func TestRenderKeyDetailsShowsPreciseTemplateProvenanceNote(t *testing.T) {
	rendered := stripANSI(Model{details: keyDetailsState{address: "ADDR", keyType: "mytemplate-v1", templateProvenanceStatus: "conflict", templateProvenanceNote: "creation template fingerprint differs"}, height: 30}.renderKeyDetails())

	if !strings.Contains(rendered, "Type:    [mytemplate-v1] [template mismatch]") {
		t.Fatalf("renderKeyDetails() missing projected template mismatch label:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Template mismatch: creation template fingerprint differs") {
		t.Fatalf("renderKeyDetails() missing precise template mismatch detail:\n%s", rendered)
	}
}

func TestRenderKeyDetailsShowsSentryPublicKey(t *testing.T) {
	rendered := stripANSI(Model{details: keyDetailsState{address: "aabbccdd", keyType: keytypes.SentryComponentEd25519V1, publicKeyHex: "aabbccdd"}, height: 30}.renderKeyDetails())

	if !strings.Contains(rendered, "Sentry public key: aabbccdd") {
		t.Fatalf("renderKeyDetails() missing sentry public key:\n%s", rendered)
	}
}

func TestRenderKeyDetailsTruncatesLongPublicKey(t *testing.T) {
	const publicKey = "0123456789abcdef0123456789abcdef0123456789abcdef"
	rendered := stripANSI(Model{details: keyDetailsState{address: "SENTRYKEY", keyType: keytypes.SentryComponentFalcon1024V1, publicKeyHex: publicKey}, height: 30}.renderKeyDetails())

	if !strings.Contains(rendered, "Sentry public key: 0123456789abcdef0123...") {
		t.Fatalf("renderKeyDetails() missing truncated sentry public key:\n%s", rendered)
	}
	if strings.Contains(rendered, publicKey) {
		t.Fatalf("renderKeyDetails() rendered full sentry public key:\n%s", rendered)
	}
}

func TestRenderKeyDetailsLabelsSentryKey(t *testing.T) {
	rendered := stripANSI(Model{
		initialNodeRole: "sentry",
		details:         keyDetailsState{address: "SENTRYKEY", keyType: keytypes.SentryComponentEd25519V1}, height: 30,
	}.renderKeyDetails())

	if !strings.Contains(rendered, "Sentry Key: SENTRYKEY") {
		t.Fatalf("renderKeyDetails() missing sentry key label:\n%s", rendered)
	}
	if strings.Contains(rendered, "Address: SENTRYKEY") {
		t.Fatalf("renderKeyDetails() used address label in sentry mode:\n%s", rendered)
	}
}

func TestHandleKeyListKeysDoesNotExportOrDeleteFromMainScreen(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		keylist: keyListState{keys: []KeyInfo{{
			Address: "ADDR",
			KeyType: "ed25519",
		}}},
	}

	nextModel, _ := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if next.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyList)
	}

	nextModel, _ = m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	next = nextModel.(Model)
	if next.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyList)
	}
	if next.del.address != "" {
		t.Fatalf("deleteAddress = %q, want empty", next.del.address)
	}
}

func TestKeyListPolicyShortcutOpensPolicyEditor(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		keylist: keyListState{keys: []KeyInfo{{
			Address: "ADDR",
			KeyType: "ed25519",
		}}},
	}

	nextModel, cmd := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	next := nextModel.(Model)
	if next.viewState != ViewPolicyEditor {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewPolicyEditor)
	}
	if next.policyEd.returnView != ViewKeyList {
		t.Fatalf("policyEditorReturnView = %v, want %v", next.policyEd.returnView, ViewKeyList)
	}
	if !next.policyEd.loading {
		t.Fatal("policyEditorLoading = false, want true")
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want policy editor load command")
	}

	rendered := stripANSI(m.View())
	if !strings.Contains(rendered, "p: Policy") {
		t.Fatalf("View() missing policy shortcut:\n%s", rendered)
	}
}

func TestHandleKeyDetailsKeysDoesNotExportFromDetailsScreen(t *testing.T) {
	m := Model{
		viewState: ViewKeyDetails,
		details:   keyDetailsState{address: "ADDR", keyType: "ed25519", teal: "int 1", saveStatus: "saved"},
	}

	nextModel, _ := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if next.viewState != ViewKeyDetails {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyDetails)
	}
}

func TestHandleKeyDetailsKeysDeletesFromDetailsScreen(t *testing.T) {
	m := Model{
		viewState: ViewKeyDetails,
		details:   keyDetailsState{address: "ADDR", keyType: "ed25519"},
	}

	nextModel, _ := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	next := nextModel.(Model)
	if next.viewState != ViewDeleteConfirm {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewDeleteConfirm)
	}
	if next.del.address != "ADDR" {
		t.Fatalf("deleteAddress = %q, want ADDR", next.del.address)
	}
	if next.del.keyType != "ed25519" {
		t.Fatalf("deleteKeyType = %q, want ed25519", next.del.keyType)
	}
	if next.del.focus != 0 {
		t.Fatalf("deleteConfirmFocus = %d, want 0", next.del.focus)
	}
}

func TestHandleKeyDetailsTKeyOpensInternalTEALDisplay(t *testing.T) {
	m := Model{
		viewState: ViewKeyDetails,
		details:   keyDetailsState{address: "ADDR", keyType: "generic", teal: "int 1"}, dataDir: "",
	}

	nextModel, cmd := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil internal viewer command", cmd)
	}
	next := nextModel.(Model)
	if next.viewState != ViewTEALFullDisplay {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewTEALFullDisplay)
	}
}

func TestHandleKeyDetailsVKeyDoesNotOpenTEALDisplay(t *testing.T) {
	m := Model{
		viewState: ViewKeyDetails,
		details:   keyDetailsState{address: "ADDR", keyType: "generic", teal: "int 1"},
	}

	nextModel, cmd := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	next := nextModel.(Model)
	if next.viewState != ViewKeyDetails {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyDetails)
	}
}

func TestHandleTEALFullDisplayEscReturnsToKeyDetails(t *testing.T) {
	m := Model{
		viewState: ViewTEALFullDisplay,
		details:   keyDetailsState{scrollOffset: 2, teal: "int 1\nint 2\nint 3"},
	}

	nextModel, cmd := m.handleTEALFullDisplayKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	next := nextModel.(Model)
	if next.viewState != ViewKeyDetails {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyDetails)
	}
	if next.details.scrollOffset != 0 {
		t.Fatalf("detailsScrollOffset = %d, want reset", next.details.scrollOffset)
	}
}

func TestHandleTEALFullDisplayPageKeysScrollByPage(t *testing.T) {
	m := Model{
		viewState: ViewTEALFullDisplay,
		details:   keyDetailsState{teal: strings.Repeat("int 1\n", 30)}, height: 17,
	}

	nextModel, _ := m.handleTEALFullDisplayKeys(tea.KeyMsg{Type: tea.KeyPgDown})
	next := nextModel.(Model)
	if next.details.scrollOffset != next.tealFullDisplayVisibleLines() {
		t.Fatalf("detailsScrollOffset after pgdown = %d, want %d",
			next.details.scrollOffset, next.tealFullDisplayVisibleLines())
	}

	nextModel, _ = next.handleTEALFullDisplayKeys(tea.KeyMsg{Type: tea.KeyPgUp})
	next = nextModel.(Model)
	if next.details.scrollOffset != 0 {
		t.Fatalf("detailsScrollOffset after pgup = %d, want 0", next.details.scrollOffset)
	}
}
