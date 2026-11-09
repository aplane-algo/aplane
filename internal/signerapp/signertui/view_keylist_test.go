// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestBuildDetailsParameterLinesFormatsAddressList(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "allowlist-test-v1",
		DisplayName: "Allowlist Test",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:  "recipients",
			Label: "Recipients",
			Type:  "address[]",
		}},
	}})

	got := buildDetailsParameterLines("allowlist-test-v1", map[string]string{
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
		KeyType:     "allowlist-test-v1",
		DisplayName: "Allowlist Test",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:  "recipients",
			Label: "Recipients",
			Type:  "address[]",
		}},
	}})

	rendered := Model{details: keyDetailsState{keyType: "allowlist-test-v1", parameters: map[string]string{
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
			{Address: "COSIGNERKEY", KeyType: witness.Falcon1024V1},
		}},
	}

	rendered := stripANSI(m.renderKeyListView())
	if strings.Contains(rendered, "Signing (1)") || strings.Contains(rendered, "Cosigner (1)") {
		t.Fatalf("signer node rendered tab controls:\n%s", rendered)
	}
	if !strings.Contains(rendered, "SIGNINGADDR") {
		t.Fatalf("signer node missing signing key:\n%s", rendered)
	}
	if strings.Contains(rendered, "COSIGNERKEY") {
		t.Fatalf("signer node showed cosigner key:\n%s", rendered)
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
			{Address: "COSIGNERKEY", KeyType: witness.Falcon1024V1},
		}},
	}

	rendered := stripANSI(m.renderKeyListView())
	if strings.Contains(rendered, "Signing (1)") || strings.Contains(rendered, "Cosigner (1)") {
		t.Fatalf("signing mode rendered tab controls:\n%s", rendered)
	}
	if !strings.Contains(rendered, "SIGNINGADDR") {
		t.Fatalf("signing mode missing signing key:\n%s", rendered)
	}
	if strings.Contains(rendered, "COSIGNERKEY") {
		t.Fatalf("signing mode showed cosigner key:\n%s", rendered)
	}
	if strings.Contains(m.viewFooterText(), "Switch tab") {
		t.Fatalf("signing mode footer advertised tab switching: %q", m.viewFooterText())
	}
}

func TestRenderKeyListViewUsesCosignerNodeWithoutTabs(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		width:     120,
		height:    24,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "COSIGNERKEY", KeyType: witness.Falcon1024V1},
		}},
	}

	rendered := stripANSI(m.renderKeyListView())
	if strings.Contains(rendered, "Signing (1)") || strings.Contains(rendered, "Cosigner (1)") {
		t.Fatalf("cosigner node rendered tab controls:\n%s", rendered)
	}
	if !strings.Contains(rendered, "COSIGNERKEY") {
		t.Fatalf("cosigner node missing cosigner key:\n%s", rendered)
	}
	if strings.Contains(rendered, "SIGNINGADDR") {
		t.Fatalf("cosigner node showed signing key:\n%s", rendered)
	}
	if strings.Contains(m.viewFooterText(), "Switch tab") {
		t.Fatalf("cosigner node footer advertised tab switching: %q", m.viewFooterText())
	}
}

func TestHandleKeyListKeysIgnoresTabOnCosignerNode(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "COSIGNERKEY", KeyType: witness.Falcon1024V1},
		}},
	}

	nextModel, _ := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyTab})
	next := nextModel.(Model)
	if next.effectiveKeyListTab() != keyListTabCosigner {
		t.Fatalf("effectiveKeyListTab after tab = %v, want cosigner", next.effectiveKeyListTab())
	}
	keys := next.filteredKeys()
	if len(keys) != 1 || keys[0].Address != "COSIGNERKEY" {
		t.Fatalf("cosigner filtered keys = %#v, want cosigner key", keys)
	}
}

func TestHandleKeyListKeysIgnoresTabsOnSignerNode(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "signer"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "COSIGNERKEY", KeyType: witness.Falcon1024V1},
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

func TestSelectKeyByAddressSwitchesToCosignerTab(t *testing.T) {
	m := Model{admin: adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}},
		keylist: keyListState{keys: []KeyInfo{
			{Address: "SIGNINGADDR", KeyType: "ed25519"},
			{Address: "COSIGNERKEY", KeyType: witness.Falcon1024V1},
		}},
	}

	m.selectKeyByAddress("COSIGNERKEY")
	if m.keylist.tab != keyListTabCosigner {
		t.Fatalf("keyListTab = %v, want cosigner", m.keylist.tab)
	}
	if m.keylist.selectedKey != 0 {
		t.Fatalf("selectedKey = %d, want first cosigner tab row", m.keylist.selectedKey)
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

func TestRenderKeyDetailsShowsCosignerPublicKey(t *testing.T) {
	rendered := stripANSI(Model{details: keyDetailsState{address: "aabbccdd", keyType: witness.Falcon1024V1, publicKeyHex: "aabbccdd"}, height: 30}.renderKeyDetails())

	if !strings.Contains(rendered, "Cosigner public key: aabbccdd") {
		t.Fatalf("renderKeyDetails() missing cosigner public key:\n%s", rendered)
	}
}

func TestRenderKeyDetailsTruncatesLongPublicKey(t *testing.T) {
	const publicKey = "0123456789abcdef0123456789abcdef0123456789abcdef"
	rendered := stripANSI(Model{details: keyDetailsState{address: "COSIGNERKEY", keyType: witness.Falcon1024V1, publicKeyHex: publicKey}, height: 30}.renderKeyDetails())

	if !strings.Contains(rendered, "Cosigner public key: 0123456789abcdef0123...") {
		t.Fatalf("renderKeyDetails() missing truncated cosigner public key:\n%s", rendered)
	}
	if strings.Contains(rendered, publicKey) {
		t.Fatalf("renderKeyDetails() rendered full cosigner public key:\n%s", rendered)
	}
}

func TestRenderKeyDetailsLabelsCosignerKey(t *testing.T) {
	rendered := stripANSI(Model{
		initialNodeRole: "cosigner",
		details:         keyDetailsState{address: "COSIGNERKEY", keyType: witness.Falcon1024V1}, height: 30,
	}.renderKeyDetails())

	if !strings.Contains(rendered, "Cosigner Key: COSIGNERKEY") {
		t.Fatalf("renderKeyDetails() missing cosigner key label:\n%s", rendered)
	}
	if strings.Contains(rendered, "Address: COSIGNERKEY") {
		t.Fatalf("renderKeyDetails() used address label in cosigner mode:\n%s", rendered)
	}
}

func TestHandleKeyListKeysDoesNotDeleteFromMainScreen(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		keylist: keyListState{keys: []KeyInfo{{
			Address: "ADDR",
			KeyType: "ed25519",
		}}},
	}

	nextModel, _ := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	next := nextModel.(Model)
	if next.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewKeyList)
	}
	if next.del.address != "" {
		t.Fatalf("deleteAddress = %q, want empty", next.del.address)
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

func TestHandleKeyDetailsSaveValidatesAddress(t *testing.T) {
	m := Model{
		viewState: ViewKeyDetails,
		details:   keyDetailsState{address: "ADDR", keyType: "generic", teal: "int 1"},
	}

	nextModel, cmd := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	next := nextModel.(Model)
	if !strings.Contains(next.details.saveStatus, "invalid account address") {
		t.Fatalf("saveStatus = %q, want invalid address error", next.details.saveStatus)
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

// Key details name a cosigned account's cosigner by the Witness Key ID the
// server projects under "cosigner": under the type's own label when it
// declares that parameter (the plain hosts), and as Cosigner when it declares
// only the public key (a composed template).
func TestBuildDetailsParameterLinesShowsTheCosigner(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{
		{KeyType: "plain-test-v1", CreationParams: []protocol.TemplateParamInfo{
			{Name: "cosigner", Label: "Cosigner Reference", Type: "string"},
			{Name: "rekey_authority", Label: "Rekey Authority", Type: "string"},
		}},
		{KeyType: "template-test-v1", CreationParams: []protocol.TemplateParamInfo{
			{Name: "cosigner_public_key", Label: "Cosigner Public Key", Type: "string"},
			{Name: "rekey_authority", Label: "Rekey Authority", Type: "string"},
		}},
	})
	parameters := map[string]string{"cosigner": "WKID-1", "rekey_authority": "refused"}
	for keyType, want := range map[string][]string{
		"plain-test-v1":    {"Cosigner Reference: WKID-1", "", "Rekey Authority: refused"},
		"template-test-v1": {"Cosigner: WKID-1", "", "Rekey Authority: refused"},
	} {
		if got := buildDetailsParameterLines(keyType, parameters); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: buildDetailsParameterLines() = %#v, want %#v", keyType, got, want)
		}
	}
}
