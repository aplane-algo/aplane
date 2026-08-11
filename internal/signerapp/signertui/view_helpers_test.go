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
	if got, want := getKeyTypeByIndex(1), "test.timed-policy.v1"; got != want {
		t.Fatalf("generate key type index 1 = %q, want %q", got, want)
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

func TestNativeFalconGenerationAndImportShowRecoveryNotice(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:           "falcon1024",
		DisplayName:       "falcon1024",
		AuthorizationKind: "native_pq",
		MnemonicWordCount: 25,
		MnemonicImport:    true,
	}})

	m := Model{
		width:  110,
		height: 30,
		forms:  formsState{importMnemonicInput: newImportMnemonicInput()},
	}
	generate := stripANSI(m.renderGenerateForm())
	importForm := stripANSI(m.renderImportForm())
	for name, rendered := range map[string]string{"generate": generate, "import": importForm} {
		for _, want := range []string{"consensus v42", "25-word", "24-word aplane.falcon1024.v1"} {
			if !strings.Contains(rendered, want) {
				t.Fatalf("%s form missing %q:\n%s", name, want, rendered)
			}
		}
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
			{Name: "sentry_public_key", Label: "Sentry public key", Type: "bytes", Required: true, MaxLength: 64},
			{Name: "note", Label: "Note", Type: "string", MaxLength: 200},
		},
	}})

	m := Model{
		width:  58,
		height: 72,
		forms: formsState{generateKeyType: 0, generateFocus: 1, genericLSigParams: map[string]string{
			"recipient":         strings.Repeat("A", 58),
			"recipients":        strings.Repeat("B", 58) + "\n" + strings.Repeat("C", 58),
			"unlock_round":      "18446744073709551615",
			"sentry_public_key": "d6fb74e10151ac3b0eaa7431b9b92c772c2a4a600c10b88cfd30169ea1ab4d0a",
			"note":              strings.Repeat("D", 200),
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
		KeyType:     "aplane.falcon1024-sentry1024.v1",
		DisplayName: "Falcon-1024 / Falcon-1024 Sentry",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:    "sentry",
			Label:   "Sentry",
			Type:    "select",
			Options: []string{"test1"},
			Default: "test1",
		}},
	}})

	m := Model{
		width:  100,
		height: 30,
		forms:  formsState{generateFocus: 0, genericLSigParams: map[string]string{"sentry": ""}, genericLSigParamModes: map[string]int{"sentry": 0}, genericLSigParamScroll: map[string]int{"sentry": 0}},
	}

	rendered := m.renderParameterModalForKeyType("aplane.falcon1024-sentry1024.v1", "GENERATE", "")
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

func TestBytesParameterFieldUsesDeclaredHexLength(t *testing.T) {
	if got := getFieldWidthForType("bytes", 64); got != 66 {
		t.Fatalf("bytes field width = %d, want 66", got)
	}
	if got := getMaxInputLengthForType("bytes", 64); got != 64 {
		t.Fatalf("bytes max input length = %d, want 64", got)
	}
}

func TestParameterModalShowsCompactPastedKeyPreview(t *testing.T) {
	defer setServerKeyTypes(nil)

	const falconPublicKeyHexLength = 1793 * 2
	const suffix = "0123456789ffffffffff"
	value := strings.Repeat("a", falconPublicKeyHexLength-len(suffix)) + suffix
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.falcon1024-allowlist-alock.v1",
		DisplayName: "Falcon Bounded Allowlist",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:      "bounded_admin_public_key",
			Label:     "Contract Admin Public Key",
			Type:      "bytes",
			Required:  true,
			MaxLength: falconPublicKeyHexLength,
		}},
	}})

	m := Model{
		viewState:       ViewGenerateParams,
		connectionState: ConnectionConnected,
		width:           100,
		height:          40,
		forms: formsState{
			generateFocus:     0,
			genericLSigParams: map[string]string{"bounded_admin_public_key": value},
		},
	}

	rendered := stripANSI(m.renderParameterModalForKeyType("aplane.falcon1024-allowlist-alock.v1", "GENERATE", ""))
	if !strings.Contains(rendered, "...") || !strings.Contains(rendered, suffix) {
		t.Fatalf("parameter modal does not show a middle-elided key with its suffix:\n%s", rendered)
	}
	if !strings.Contains(rendered, "REPLACE KEY") || !strings.Contains(rendered, "3586 characters") {
		t.Fatalf("parameter modal does not show replace action and key length:\n%s", rendered)
	}
	if strings.Contains(rendered, " #") || strings.Contains(rendered, " |") {
		t.Fatalf("parameter modal still shows the removed scrollbar:\n%s", rendered)
	}
	if !firstRoundedBoxHasBottomBorder(rendered) {
		t.Fatalf("read-only parameter field clipped its bottom border:\n%s", rendered)
	}

	m.forms.genericLSigPasteParam = "bounded_admin_public_key"
	rendered = stripANSI(m.renderParameterModalForKeyType("aplane.falcon1024-allowlist-alock.v1", "GENERATE", ""))
	if !strings.Contains(rendered, "Paste key now") || !strings.Contains(rendered, "WAITING FOR PASTE") {
		t.Fatalf("paste capture state is not visible:\n%s", rendered)
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
		width:     58,
		height:    18,
		viewState: ViewGenerateParams,
		forms: formsState{generateKeyType: 0, generateFocus: 0, genericLSigParams: map[string]string{
			"recipients": strings.Join([]string{
				strings.Repeat("A", 58),
				strings.Repeat("B", 58),
				strings.Repeat("C", 58),
				strings.Repeat("D", 58),
				strings.Repeat("E", 58),
				strings.Repeat("F", 58),
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
