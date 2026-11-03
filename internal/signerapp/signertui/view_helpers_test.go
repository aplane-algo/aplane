// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestRenderPopupConstrainsToPanelWidthAndHeight(t *testing.T) {
	m := Model{viewState: ViewGenerateDisplay, width: 42, height: 10}
	bodyLines := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		bodyLines = append(bodyLines, fmt.Sprintf("line-%02d", i))
	}

	view := m.renderPopup(80, strings.Join(bodyLines, "\n"))
	for _, line := range strings.Split(view, "\n") {
		if width := visibleWidth(line); width > m.width {
			t.Fatalf("popup line width = %d, want <= %d\nline: %q\nview:\n%s",
				width, m.width, stripANSI(line), stripANSI(view))
		}
	}
	if lines := visibleLineCount(view); lines > m.height {
		t.Fatalf("popup line count = %d, want <= %d\n%s", lines, m.height, stripANSI(view))
	}
	clean := stripANSI(view)
	if !strings.Contains(clean, "line-00") || !strings.Contains(clean, "Panel lines") {
		t.Fatalf("overflowing popup does not show its first page and scroll status:\n%s", clean)
	}

	next, _ := m.handleKeyPress(tea.KeyMsg{Type: tea.KeyCtrlEnd})
	m = next.(Model)
	view = m.renderPopup(80, strings.Join(bodyLines, "\n"))
	clean = stripANSI(view)
	if !strings.Contains(clean, "line-19") {
		t.Fatalf("panel end does not show final content line:\n%s", clean)
	}
	if strings.Contains(clean, "line-00") {
		t.Fatalf("panel end still shows first content line:\n%s", clean)
	}
}

func TestServerKeyTypesDriveGenerateAndImportOptions(t *testing.T) {
	defer setServerKeyTypes(nil)

	setServerKeyTypes([]protocol.KeyTypeInfo{
		{
			KeyType:           "ed25519",
			DisplayName:       "Ed25519",
			MnemonicWordCount: 25,
			MnemonicImport:    true,
		},
		{
			KeyType:           "test.timed-policy.v1",
			DisplayName:       "Timed Allowlist",
			Description:       "Generic timed allowlist LogicSig",
			MnemonicWordCount: 0,
			CreationParams: []protocol.TemplateParamInfo{
				{Name: "unlock_round", Label: "Unlock Round", Type: "uint64", Required: true},
			},
		},
		{
			KeyType:           "aplane.falcon1024-allowlist.v1",
			DisplayName:       "Falcon Allowlist",
			MnemonicWordCount: 24,
			MnemonicImport:    false,
			CreationParams: []protocol.TemplateParamInfo{
				{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 30},
			},
		},
		{
			KeyType:           "aplane.falcon1024.v1",
			DisplayName:       "Falcon-1024",
			MnemonicWordCount: 24,
			MnemonicImport:    true,
		},
		{
			KeyType:           "aplane.ed25519.v1",
			DisplayName:       "Example DSA",
			MnemonicWordCount: 24,
			MnemonicImport:    false,
		},
	})

	if got, want := getKeyTypeCount(), 5; got != want {
		t.Fatalf("getKeyTypeCount() = %d, want %d", got, want)
	}
	if got, want := getImportKeyTypeCount(), 2; got != want {
		t.Fatalf("getImportKeyTypeCount() = %d, want %d", got, want)
	}
	// Native key types come first, then published ones, each alphabetical.
	wantGenerate := []string{"ed25519", "aplane.ed25519.v1", "aplane.falcon1024-allowlist.v1", "aplane.falcon1024.v1", "test.timed-policy.v1"}
	for i, want := range wantGenerate {
		if got := getKeyTypeByIndex(i); got != want {
			t.Fatalf("generate key type index %d = %q, want %q", i, got, want)
		}
	}
	if got := strings.Join(getGenerateKeyTypeOptions(), ","); got != strings.Join(wantGenerate, ",") {
		t.Fatalf("generate options = %s, want %s", got, strings.Join(wantGenerate, ","))
	}
	if got, want := getImportKeyTypeByIndex(1), "aplane.falcon1024.v1"; got != want {
		t.Fatalf("import key type index 1 = %q, want %q", got, want)
	}
	if got, want := getExpectedImportWordCount(1), 24; got != want {
		t.Fatalf("import word count = %d, want %d", got, want)
	}

	spec := getParamSpecForKeyType("aplane.falcon1024-allowlist.v1")
	if spec == nil {
		t.Fatal("getParamSpecForKeyType() = nil, want server-backed params")
		return
	}
	if got, want := spec.Params[0].MaxItems, 30; got != want {
		t.Fatalf("MaxItems = %d, want %d", got, want)
	}
}

func TestKeyTypeSelectionOrderClustersNativeFirst(t *testing.T) {
	got := sortKeyTypesForSelection([]string{
		"zeta.custom.v1", "falcon1024", "aplane.rotating-triple-xmss.v1",
		"ed25519", "aplane.falcon1024.v1", "acme.allowlist.v2",
	})
	want := []string{
		"ed25519", "falcon1024",
		"acme.allowlist.v2", "aplane.falcon1024.v1", "aplane.rotating-triple-xmss.v1", "zeta.custom.v1",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", got, want)
	}
	if n := nativeKeyTypeCount(got); n != 2 {
		t.Fatalf("native count = %d, want 2", n)
	}
}

func TestSeparateKeyTypeClustersInsertsOneBlankRow(t *testing.T) {
	rows := []string{"ed25519", "falcon1024", "aplane.a.v1", "aplane.b.v1"}
	got, selected := separateKeyTypeClusters(rows, 2, 2)
	if strings.Join(got, "|") != "ed25519|falcon1024||aplane.a.v1|aplane.b.v1" || selected != 3 {
		t.Fatalf("rows = %q selected %d", got, selected)
	}
	if _, selected := separateKeyTypeClusters(rows, 2, 1); selected != 1 {
		t.Fatalf("native selection moved to %d", selected)
	}
	for _, native := range []int{0, len(rows)} {
		if got, selected := separateKeyTypeClusters(rows, native, 1); len(got) != len(rows) || selected != 1 {
			t.Fatalf("single cluster (native=%d) got separator: %q selected %d", native, got, selected)
		}
	}
}

func TestGenerateFormShowsClustersWithSeparator(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{
		{KeyType: "aplane.falcon1024.v1"}, {KeyType: "falcon1024"}, {KeyType: "acme.custom.v1"}, {KeyType: "ed25519"},
	})
	m := Model{width: 100, height: 40, viewState: ViewGenerateForm}
	m.forms.generateKeyType = 2 // acme.custom.v1, the first published key type
	var listed []string
	for _, line := range strings.Split(stripANSI(m.renderGenerateForm()), "\n") {
		line = strings.TrimSpace(strings.Trim(line, "║"))
		if line == "" && len(listed) > 0 && len(listed) < 4 {
			listed = append(listed, "")
			continue
		}
		for _, name := range []string{"ed25519", "falcon1024", "> acme.custom.v1", "aplane.falcon1024.v1"} {
			if line == name {
				listed = append(listed, line)
			}
		}
	}
	want := "ed25519|falcon1024||> acme.custom.v1|aplane.falcon1024.v1"
	if got := strings.Join(listed, "|"); got != want {
		t.Fatalf("listed = %q, want %q\n%s", got, want, stripANSI(m.renderGenerateForm()))
	}
}

func TestProtocolParamInfosToDefsPreservesInputModes(t *testing.T) {
	defs := protocolParamInfosToDefs([]protocol.TemplateParamInfo{{
		Name: "preimage",
		Type: "bytes",
		InputModes: []protocol.InputModeInfo{
			{Name: "hash", Label: "Hash"},
			{Name: "preimage", Label: "Preimage", Transform: "sha256", ByteLength: 32, InputType: "string"},
		},
	}})
	if len(defs) != 1 || len(defs[0].InputModes) != 2 {
		t.Fatalf("defs = %#v, want input modes", defs)
	}
	want := lsigprovider.InputMode{Name: "preimage", Label: "Preimage", Transform: "sha256", ByteLength: 32, InputType: "string"}
	if defs[0].InputModes[1] != want {
		t.Fatalf("input mode = %#v, want %#v", defs[0].InputModes[1], want)
	}
}

func TestGenerateFormDoesNotShowParameterCountSummary(t *testing.T) {
	defer setServerKeyTypes(nil)

	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.falcon1024-allowlist.v1",
		DisplayName: "Falcon Allowlist",
		Description: "Falcon-1024 signature restricted to a fixed set of receiver addresses",
		CreationParams: []protocol.TemplateParamInfo{
			{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 30},
		},
	}})

	rendered := stripANSI(Model{width: 110, height: 30}.renderGenerateForm())
	if strings.Contains(rendered, "(Falcon Allowlist)") {
		t.Fatalf("generate form rendered selected name in parentheses:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Falcon Allowlist") {
		t.Fatalf("generate form missing selected name footer:\n%s", rendered)
	}
	if strings.Contains(rendered, "Falcon-1024 signature restricted to a fixed set of receiver addresses") {
		t.Fatalf("generate form rendered selected description instead of name:\n%s", rendered)
	}
	if strings.Contains(rendered, "parameters to configure") {
		t.Fatalf("generate form rendered parameter count summary:\n%s", rendered)
	}
}

func TestParameterModalFieldsFitPopupWidth(t *testing.T) {
	defer setServerKeyTypes(nil)

	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "test.param-fit.v1",
		DisplayName: "Param Fit Test",
		Description: "Exercises parameter field sizing",
		CreationParams: []protocol.TemplateParamInfo{
			{Name: "recipient", Label: "Recipient", Type: "address", Required: true},
			{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true},
			{Name: "unlock_round", Label: "Unlock Round", Type: "uint64", Required: true},
			{Name: "cosigner_public_key", Label: "Cosigner public key", Type: "bytes", Required: true, MaxLength: 64},
			{Name: "note", Label: "Note", Type: "string", MaxLength: 200},
		},
	}})

	m := Model{
		width:  58,
		height: 72,
		forms: formsState{generateKeyType: 0, generateFocus: 1, genericLSigParams: map[string]string{
			"recipient":           strings.Repeat("A", 58),
			"recipients":          strings.Repeat("B", 58) + "\n" + strings.Repeat("C", 58),
			"unlock_round":        "18446744073709551615",
			"cosigner_public_key": "d6fb74e10151ac3b0eaa7431b9b92c772c2a4a600c10b88cfd30169ea1ab4d0a",
			"note":                strings.Repeat("D", 200),
		}, genericLSigParamModes: map[string]int{}, genericLSigParamScroll: map[string]int{
			"recipients": 0,
		}},
	}

	rendered := m.renderParameterModalForKeyType("test.param-fit.v1", "GENERATE", "")
	for _, line := range strings.Split(rendered, "\n") {
		if width := visibleWidth(line); width > m.width {
			t.Fatalf("parameter modal line width = %d, want <= %d\nline: %q\nview:\n%s",
				width, m.width, stripANSI(line), stripANSI(rendered))
		}
	}
}

func TestParameterModalFocusedSelectShowsDefaultOption(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.falcon1024-cosigner1024.v1",
		DisplayName: "Falcon-1024 / Falcon-1024 Cosigner",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:    "cosigner",
			Label:   "Cosigner",
			Type:    "select",
			Options: []string{"test1"},
			Default: "test1",
		}},
	}})

	m := Model{
		width:  100,
		height: 30,
		forms:  formsState{generateFocus: 0, genericLSigParams: map[string]string{"cosigner": ""}, genericLSigParamModes: map[string]int{"cosigner": 0}, genericLSigParamScroll: map[string]int{"cosigner": 0}},
	}

	rendered := m.renderParameterModalForKeyType("aplane.falcon1024-cosigner1024.v1", "GENERATE", "")
	if !strings.Contains(stripANSI(rendered), "test1_") {
		t.Fatalf("focused select did not render default option:\n%s", stripANSI(rendered))
	}
}

func TestParameterModalMarksOnlyOptionalParameters(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "test.generic-policy.v1",
		DisplayName: "Allowlist",
		CreationParams: []protocol.TemplateParamInfo{
			{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true},
			{Name: "allowed_optin_assets", Label: "Approved Opt-In Assets", Type: "uint64[]", Required: false},
		},
	}})

	m := Model{
		viewState:       ViewGenerateParams,
		connectionState: ConnectionConnected,
		width:           100,
		height:          40,
		forms: formsState{
			generateFocus:         1,
			genericLSigParams:     map[string]string{"recipients": "", "allowed_optin_assets": ""},
			genericLSigParamModes: map[string]int{},
			genericLSigParamScroll: map[string]int{
				"recipients":           0,
				"allowed_optin_assets": 0,
			},
		},
	}

	rendered := stripANSI(m.renderParameterModalForKeyType("test.generic-policy.v1", "GENERATE", ""))
	if !strings.Contains(rendered, "Recipients:") {
		t.Fatalf("required label missing:\n%s", rendered)
	}
	if strings.Contains(rendered, "Recipients (required):") {
		t.Fatalf("required marker should not be shown:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Approved Opt-In Assets (optional):") {
		t.Fatalf("optional marker missing:\n%s", rendered)
	}
}

func TestParameterModalButtonOmitsKeyType(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:        "test.generic-policy.v1",
		DisplayName:    "Allowlist",
		CreationParams: []protocol.TemplateParamInfo{{Name: "recipients", Label: "Recipients", Type: "address[]"}},
	}})

	m := Model{
		width:  100,
		height: 40,
		forms: formsState{
			genericLSigParams:      map[string]string{"recipients": ""},
			genericLSigParamModes:  map[string]int{},
			genericLSigParamScroll: map[string]int{"recipients": 0},
		},
	}

	for _, focus := range []int{0, 1} {
		m.forms.generateFocus = focus
		for _, verb := range []string{"GENERATE", "IMPORT"} {
			rendered := stripANSI(m.renderParameterModalForKeyType("test.generic-policy.v1", verb, ""))
			if !strings.Contains(rendered, "[ "+verb+" ]") {
				t.Fatalf("focus %d: button is not [ %s ]:\n%s", focus, verb, rendered)
			}
			if strings.Contains(rendered, "ALLOWLIST") {
				t.Fatalf("focus %d: button names the key type:\n%s", focus, rendered)
			}
		}
	}
}

func TestBytesParameterFieldUsesDeclaredHexLength(t *testing.T) {
	if got := getFieldWidthForType("bytes", 64); got != 66 {
		t.Fatalf("bytes field width = %d, want 66", got)
	}
	if got := getMaxInputLengthForType("bytes", 64); got != 64 {
		t.Fatalf("bytes max input length = %d, want 64", got)
	}
}

func TestParameterModalShowsContractAdminReferencePath(t *testing.T) {
	defer setServerKeyTypes(nil)

	const suffix = "B6VKKS7RQNVGBTM2ZPE3ICM2W7DLBNM62JKE3UVV4D4KRY3ND7IQ.wit.json"
	value := "/media/cold/" + strings.Repeat("directory/", 12) + suffix
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.falcon1024-allowlist-alock.v1",
		DisplayName: "Falcon Bounded Allowlist",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:      "bounded_admin_public_key",
			Label:     "Contract Admin Public Key",
			Type:      "bytes",
			Required:  true,
			MaxLength: 1793 * 2,
		}},
	}})

	m := Model{
		viewState:       ViewGenerateParams,
		connectionState: ConnectionConnected,
		width:           100,
		height:          40,
		forms: formsState{
			generateFocus:     1,
			genericLSigParams: map[string]string{"bounded_admin_public_key": value},
		},
	}

	rendered := stripANSI(m.renderParameterModalForKeyType("aplane.falcon1024-allowlist-alock.v1", "GENERATE", ""))
	if !strings.Contains(rendered, "Contract Admin Reference File (.wit.json)") || !strings.Contains(rendered, "...") || !strings.Contains(rendered, "D7IQ.wit.json") {
		t.Fatalf("parameter modal does not show the public reference path:\n%s", rendered)
	}
	if strings.Contains(rendered, "PASTE KEY") || strings.Contains(rendered, "REPLACE KEY") {
		t.Fatalf("parameter modal still shows the removed paste action:\n%s", rendered)
	}
	if strings.Contains(rendered, " #") || strings.Contains(rendered, " |") {
		t.Fatalf("parameter modal still shows the removed scrollbar:\n%s", rendered)
	}
	if !firstRoundedBoxHasBottomBorder(rendered) {
		t.Fatalf("reference path field clipped its bottom border:\n%s", rendered)
	}

	m.forms.generateFocus = 0
	rendered = stripANSI(m.renderParameterModalForKeyType("aplane.falcon1024-allowlist-alock.v1", "GENERATE", ""))
	if !strings.Contains(rendered, "D7IQ.wit.json_") {
		t.Fatalf("editing reference path does not show its suffix:\n%s", rendered)
	}
}

func TestParameterModalMultilineFieldBottomFitsShortPane(t *testing.T) {
	defer setServerKeyTypes(nil)

	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.falcon1024-allowlist.v1",
		DisplayName: "Falcon Allowlist",
		CreationParams: []protocol.TemplateParamInfo{
			{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 30},
		},
	}})

	m := Model{
		width:     MinWidth,
		height:    MinHeight,
		viewState: ViewGenerateParams,
		forms: formsState{generateKeyType: 0, generateFocus: 0, genericLSigParams: map[string]string{
			"recipients": strings.Join([]string{
				strings.Repeat("A", 58),
				strings.Repeat("B", 58),
				strings.Repeat("C", 58),
				strings.Repeat("D", 58),
				strings.Repeat("E", 58),
				strings.Repeat("F", 58),
				strings.Repeat("G", 58),
				strings.Repeat("H", 58),
				strings.Repeat("I", 58),
				strings.Repeat("J", 58),
				strings.Repeat("K", 58),
				strings.Repeat("L", 58),
			}, "\n"),
		}, genericLSigParamModes: map[string]int{}, genericLSigParamScroll: map[string]int{
			"recipients": 0,
		}},
	}

	rendered := m.View()
	if lines := visibleLineCount(rendered); lines > m.height {
		t.Fatalf("parameter modal line count = %d, want <= %d\n%s", lines, m.height, stripANSI(rendered))
	}
	if !firstRoundedBoxHasBottomBorder(stripANSI(rendered)) {
		t.Fatalf("parameter modal clipped the multiline input bottom border:\n%s", stripANSI(rendered))
	}
}

func firstRoundedBoxHasBottomBorder(rendered string) bool {
	inBox := false
	for _, line := range strings.Split(rendered, "\n") {
		if strings.Contains(line, "╭") && strings.Contains(line, "╮") {
			inBox = true
			continue
		}
		if inBox && strings.Contains(line, "╰") && strings.Contains(line, "╯") {
			return true
		}
		if inBox && strings.Contains(line, "╭") {
			return false
		}
	}
	return false
}
