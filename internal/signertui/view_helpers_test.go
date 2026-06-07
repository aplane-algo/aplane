// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestRenderPopupConstrainsToPanelWidthAndHeight(t *testing.T) {
	m := Model{width: 42, height: 10}
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
			KeyType:           "aplane.timed-whitelist.v1",
			DisplayName:       "Timed Whitelist",
			Description:       "Generic timed whitelist LogicSig",
			MnemonicWordCount: 0,
			CreationParams: []protocol.TemplateParamInfo{
				{Name: "unlock_round", Label: "Unlock Round", Type: "uint64", Required: true},
			},
		},
		{
			KeyType:           "aplane.falcon1024-whitelist.v1",
			DisplayName:       "Falcon Whitelist",
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
			KeyType:           "aplane.ecdsak1.v1",
			DisplayName:       "ECDSA secp256k1",
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
	if got, want := getKeyTypeByIndex(1), "aplane.timed-whitelist.v1"; got != want {
		t.Fatalf("generate key type index 1 = %q, want %q", got, want)
	}
	if got, want := getImportKeyTypeByIndex(1), "aplane.falcon1024.v1"; got != want {
		t.Fatalf("import key type index 1 = %q, want %q", got, want)
	}
	if got, want := getExpectedImportWordCount(1), 24; got != want {
		t.Fatalf("import word count = %d, want %d", got, want)
	}

	spec := getParamSpecForKeyType("aplane.falcon1024-whitelist.v1")
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
		KeyType:     "aplane.falcon1024-whitelist.v1",
		DisplayName: "Falcon Whitelist",
		Description: "Falcon-1024 signature restricted to a fixed set of receiver addresses",
		CreationParams: []protocol.TemplateParamInfo{
			{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 30},
		},
	}})

	rendered := stripANSI(Model{width: 110, height: 30}.renderGenerateForm())
	if strings.Contains(rendered, "(Falcon Whitelist)") {
		t.Fatalf("generate form rendered selected name in parentheses:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Falcon Whitelist") {
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
			{Name: "attestor_public_key", Label: "Attestor public key", Type: "bytes", Required: true, MaxLength: 64},
			{Name: "note", Label: "Note", Type: "string", MaxLength: 200},
		},
	}})

	m := Model{
		width:           58,
		height:          72,
		generateKeyType: 0,
		generateFocus:   1,
		genericLSigParams: map[string]string{
			"recipient":           strings.Repeat("A", 58),
			"recipients":          strings.Repeat("B", 58) + "\n" + strings.Repeat("C", 58),
			"unlock_round":        "18446744073709551615",
			"attestor_public_key": "d6fb74e10151ac3b0eaa7431b9b92c772c2a4a600c10b88cfd30169ea1ab4d0a",
			"note":                strings.Repeat("D", 200),
		},
		genericLSigParamModes: map[string]int{},
		genericLSigParamScroll: map[string]int{
			"recipients": 0,
		},
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
		KeyType:     "aplane.falcon1024-sentry-falcon1024.v1",
		DisplayName: "Falcon-1024 / Falcon-1024 Attested",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:    "attestor",
			Label:   "Attestor",
			Type:    "select",
			Options: []string{"test1"},
			Default: "test1",
		}},
	}})

	m := Model{
		width:                  100,
		height:                 30,
		generateFocus:          0,
		genericLSigParams:      map[string]string{"attestor": ""},
		genericLSigParamModes:  map[string]int{"attestor": 0},
		genericLSigParamScroll: map[string]int{"attestor": 0},
	}

	rendered := m.renderParameterModalForKeyType("aplane.falcon1024-sentry-falcon1024.v1", "GENERATE", "")
	if !strings.Contains(stripANSI(rendered), "test1_") {
		t.Fatalf("focused select did not render default option:\n%s", stripANSI(rendered))
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

func TestParameterModalMultilineFieldBottomFitsShortPane(t *testing.T) {
	defer setServerKeyTypes(nil)

	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.falcon1024-whitelist.v1",
		DisplayName: "Falcon Whitelist",
		CreationParams: []protocol.TemplateParamInfo{
			{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 30},
		},
	}})

	m := Model{
		width:           58,
		height:          18,
		viewState:       ViewGenerateParams,
		generateKeyType: 0,
		generateFocus:   0,
		genericLSigParams: map[string]string{
			"recipients": strings.Join([]string{
				strings.Repeat("A", 58),
				strings.Repeat("B", 58),
				strings.Repeat("C", 58),
				strings.Repeat("D", 58),
				strings.Repeat("E", 58),
				strings.Repeat("F", 58),
			}, "\n"),
		},
		genericLSigParamModes: map[string]int{},
		genericLSigParamScroll: map[string]int{
			"recipients": 0,
		},
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
