// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/protocol"
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

	rendered := Model{
		detailsKeyType: "whitelist-test-v1",
		detailsParameters: map[string]string{
			"recipients": "ADDR1,ADDR2",
		},
		height: 30,
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
		keys: []KeyInfo{{
			Address: address,
			KeyType: "ed25519",
		}},
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
		keys: []KeyInfo{{
			Address:                  "ADDR",
			KeyType:                  "mytemplate-v1",
			TemplateProvenanceStatus: "conflict",
		}},
	}

	rendered := stripANSI(m.renderKeyListView())
	if !strings.Contains(rendered, "[mytemplate-v1] [template provenance]") {
		t.Fatalf("renderKeyListView() missing template provenance status:\n%s", rendered)
	}
}

func TestRenderKeyDetailsShowsPreciseTemplateProvenanceNote(t *testing.T) {
	rendered := stripANSI(Model{
		detailsAddress:                  "ADDR",
		detailsKeyType:                  "mytemplate-v1",
		detailsTemplateProvenanceStatus: "conflict",
		detailsTemplateProvenanceNote:   "creation template fingerprint differs",
		height:                          30,
	}.renderKeyDetails())

	if !strings.Contains(rendered, "Type:    [mytemplate-v1] [template provenance]") {
		t.Fatalf("renderKeyDetails() missing projected template provenance label:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Template provenance: creation template fingerprint differs") {
		t.Fatalf("renderKeyDetails() missing precise template provenance detail:\n%s", rendered)
	}
}

func TestRenderKeyDetailsShowsAttestorPublicKey(t *testing.T) {
	rendered := stripANSI(Model{
		detailsAddress:      "aabbccdd",
		detailsKeyType:      keytypes.AttestorComponentEd25519V1,
		detailsPublicKeyHex: "aabbccdd",
		height:              30,
	}.renderKeyDetails())

	if !strings.Contains(rendered, "Attestor public key: aabbccdd") {
		t.Fatalf("renderKeyDetails() missing attestor public key:\n%s", rendered)
	}
}

func TestHandleKeyListKeysDoesNotExportOrDeleteFromMainScreen(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		keys: []KeyInfo{{
			Address: "ADDR",
			KeyType: "ed25519",
		}},
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
	if next.deleteAddress != "" {
		t.Fatalf("deleteAddress = %q, want empty", next.deleteAddress)
	}
}

func TestKeyListPolicyShortcutOpensReadOnlyViewer(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		keys: []KeyInfo{{
			Address: "ADDR",
			KeyType: "ed25519",
		}},
	}

	nextModel, cmd := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	next := nextModel.(Model)
	if next.viewState != ViewPolicyViewer {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewPolicyViewer)
	}
	if next.policyViewReturnView != ViewKeyList {
		t.Fatalf("policyViewReturnView = %v, want %v", next.policyViewReturnView, ViewKeyList)
	}
	if !next.policyViewLoading {
		t.Fatal("policyViewLoading = false, want true")
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want policy snapshot request command")
	}

	rendered := stripANSI(m.View())
	if !strings.Contains(rendered, "p: Policy") {
		t.Fatalf("View() missing policy shortcut:\n%s", rendered)
	}
}

func TestPolicyViewerReturnsToKeyListWhenOpenedFromKeyList(t *testing.T) {
	m := Model{
		viewState:               ViewPolicyViewer,
		policyViewReturnView:    ViewKeyList,
		policyViewLoaded:        true,
		policyViewSelectedGuard: 0,
	}

	nextModel, cmd := m.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	next := nextModel.(Model)
	if next.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyList)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}

func TestHandleKeyDetailsKeysDoesNotExportFromDetailsScreen(t *testing.T) {
	m := Model{
		viewState:         ViewKeyDetails,
		detailsAddress:    "ADDR",
		detailsKeyType:    "ed25519",
		detailsTEAL:       "int 1",
		detailsSaveStatus: "saved",
	}

	nextModel, _ := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if next.viewState != ViewKeyDetails {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyDetails)
	}
}

func TestHandleKeyDetailsKeysDeletesFromDetailsScreen(t *testing.T) {
	m := Model{
		viewState:      ViewKeyDetails,
		detailsAddress: "ADDR",
		detailsKeyType: "ed25519",
	}

	nextModel, _ := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	next := nextModel.(Model)
	if next.viewState != ViewDeleteConfirm {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewDeleteConfirm)
	}
	if next.deleteAddress != "ADDR" {
		t.Fatalf("deleteAddress = %q, want ADDR", next.deleteAddress)
	}
	if next.deleteKeyType != "ed25519" {
		t.Fatalf("deleteKeyType = %q, want ed25519", next.deleteKeyType)
	}
	if next.deleteConfirmFocus != 0 {
		t.Fatalf("deleteConfirmFocus = %d, want 0", next.deleteConfirmFocus)
	}
}

func TestHandleKeyDetailsTKeyOpensInternalTEALDisplay(t *testing.T) {
	m := Model{
		viewState:      ViewKeyDetails,
		detailsAddress: "ADDR",
		detailsKeyType: "generic",
		detailsTEAL:    "int 1",
		dataDir:        "",
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
		viewState:      ViewKeyDetails,
		detailsAddress: "ADDR",
		detailsKeyType: "generic",
		detailsTEAL:    "int 1",
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
		viewState:           ViewTEALFullDisplay,
		detailsScrollOffset: 2,
		detailsTEAL:         "int 1\nint 2\nint 3",
	}

	nextModel, cmd := m.handleTEALFullDisplayKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	next := nextModel.(Model)
	if next.viewState != ViewKeyDetails {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyDetails)
	}
	if next.detailsScrollOffset != 0 {
		t.Fatalf("detailsScrollOffset = %d, want reset", next.detailsScrollOffset)
	}
}

func TestHandleTEALFullDisplayPageKeysScrollByPage(t *testing.T) {
	m := Model{
		viewState:   ViewTEALFullDisplay,
		detailsTEAL: strings.Repeat("int 1\n", 30),
		height:      17,
	}

	nextModel, _ := m.handleTEALFullDisplayKeys(tea.KeyMsg{Type: tea.KeyPgDown})
	next := nextModel.(Model)
	if next.detailsScrollOffset != next.tealFullDisplayVisibleLines() {
		t.Fatalf("detailsScrollOffset after pgdown = %d, want %d",
			next.detailsScrollOffset, next.tealFullDisplayVisibleLines())
	}

	nextModel, _ = next.handleTEALFullDisplayKeys(tea.KeyMsg{Type: tea.KeyPgUp})
	next = nextModel.(Model)
	if next.detailsScrollOffset != 0 {
		t.Fatalf("detailsScrollOffset after pgup = %d, want 0", next.detailsScrollOffset)
	}
}
