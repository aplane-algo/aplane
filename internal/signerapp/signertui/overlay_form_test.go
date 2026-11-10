// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

const (
	plainFalconKeyType  = "aplane.falcon1024.v1"
	plainEd25519KeyType = "aplane.ed25519.v1"
	// boundedHostKeyType is the plain host the bounded tests use.
	boundedHostKeyType = plainFalconKeyType
)

// overlayInventory reports the overlay types as the signer does, with the
// providers' own parameters, so the form is built from what production declares.
func overlayInventory(t *testing.T) []protocol.KeyTypeInfo {
	t.Helper()
	clientreg.RegisterClient()
	var infos []protocol.KeyTypeInfo
	for _, keyType := range []string{plainFalconKeyType, plainEd25519KeyType} {
		provider := lsigprovider.Get(keyType)
		if provider == nil {
			t.Fatalf("%s is not registered", keyType)
		}
		info := protocol.KeyTypeInfo{
			KeyType:                  keyType,
			DisplayName:              provider.DisplayName(),
			CosignerComponentKeyType: witness.Falcon1024V1,
			PerKeyContract:           true,
			BoundarySchema:           boundary.SchemaV1,
		}
		for _, def := range provider.CreationParams() {
			info.CreationParams = append(info.CreationParams, protocol.TemplateParamInfo{
				Name: def.Name, Label: def.Label, Description: def.Description, Type: def.Type,
				Required: def.Required, MaxLength: def.MaxLength, Options: def.Options,
				MinItems: def.MinItems, MaxItems: def.MaxItems, Min: def.Min, Max: def.Max, Default: def.Default,
			})
		}
		infos = append(infos, info)
	}
	setServerKeyTypes(infos)
	t.Cleanup(func() { setServerKeyTypes(nil) })
	return infos
}

func testAddress(seed byte) string {
	return types.Address{seed, 0x11, 0x22}.String()
}

// The preset screen's choices, as overlayForm takes them: an index into
// boundary.Presets(), or one of these.
const (
	noBounds     = -1
	customBounds = -2
)

// overlayForm opens Generate's form for keyType through a preset screen choice,
// as Enter on the key type list and the preset screen does.
func overlayForm(t *testing.T, keyType string, presetIndex int) Model {
	t.Helper()
	index, ok := keyTypeIndex(keyType, getKeyTypeCount(), getKeyTypeByIndex)
	if !ok {
		t.Fatalf("%s is not on the Generate list", keyType)
	}
	m := Model{viewState: ViewGenerateForm, cosigner: cosignerState{loaded: true}}
	m.forms.generateKeyType = index
	next, _ := m.handleGenerateFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.viewState != ViewBoundaryPreset {
		t.Fatalf("%s: view = %v, want the preset screen", keyType, m.viewState)
	}
	switch presetIndex {
	case noBounds:
		m.forms.boundaryPresetIndex = 0
	case customBounds:
		m.forms.boundaryPresetIndex = len(boundary.Presets()) + 1
	default:
		m.forms.boundaryPresetIndex = presetIndex + 1
	}
	next, _ = m.handleBoundaryPresetKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.viewState != ViewGenerateParams {
		t.Fatalf("%s: view = %v, want the parameter form", keyType, m.viewState)
	}
	return m
}

func (m Model) formSpec(t *testing.T) *paramSpec {
	t.Helper()
	spec := m.paramSpecFor(m.generateSelection())
	if spec == nil || !spec.Overlay {
		t.Fatalf("%s: not the overlay form", m.generateSelection())
	}
	return spec
}

func paramNames(params []lsigprovider.ParameterDef) []string {
	names := make([]string, len(params))
	for i, param := range params {
		names[i] = param.Name
	}
	return names
}

// pressOnField focuses the named field and sends a key there.
func (m Model) pressOnField(t *testing.T, name string, key tea.KeyMsg) Model {
	t.Helper()
	index := slices.Index(paramNames(m.formSpec(t).Params), name)
	if index < 0 {
		t.Fatalf("the form has no %s field", name)
	}
	m.forms.generateFocus = index
	next, _ := m.handleGenerateParamsKeys(key)
	return next.(Model)
}

// The bounds come first as one group, then the three overlay controls, and the
// raw cosigner key and list root are never fields.
func TestOverlayFormPutsTheBoundsBeforeTheOverlays(t *testing.T) {
	overlayInventory(t)
	for _, test := range []struct {
		keyType string
		preset  int
		bounds  []string
	}{
		{plainFalconKeyType, noBounds, nil},
		{plainEd25519KeyType, noBounds, nil},
		{boundedHostKeyType, 0, []string{boundary.ParameterRecipients}},
		{boundedHostKeyType, 2, []string{boundary.ParameterRecipients}},
		{plainEd25519KeyType, 1, []string{boundary.ParameterRecipients}},
		{boundedHostKeyType, customBounds, customBoundsPreset.Fields},
		{plainEd25519KeyType, customBounds, customBoundsPreset.Fields},
	} {
		spec := overlayForm(t, test.keyType, test.preset).formSpec(t)
		want := append(append([]string(nil), test.bounds...), overlayCosigner, overlayList, overlayRekey)
		if got := paramNames(spec.Params); !slices.Equal(got, want) {
			t.Errorf("%s preset %d: fields = %v, want %v", test.keyType, test.preset, got, want)
		}
		wantSections := []paramSection{{Start: len(test.bounds), Title: overlaySectionOverlays}}
		if len(test.bounds) > 0 {
			wantSections = append([]paramSection{{Start: 0, Title: overlaySectionBounds}}, wantSections...)
		}
		if !slices.Equal(spec.Sections, wantSections) {
			t.Errorf("%s preset %d: sections = %v", test.keyType, test.preset, spec.Sections)
		}
	}
}

// Each type offers every rekey setting it declares that fits the list and the
// cosigner: plus cosigned only with both, the general type no refused rekey.
func TestOverlayRekeyControlOffersWhatTheTypeDeclares(t *testing.T) {
	overlayInventory(t)
	for _, test := range []struct {
		keyType          string
		preset           int
		listed, cosigned bool
		want             []string
	}{
		{plainFalconKeyType, noBounds, false, false, []string{boundary.RekeyRefused, boundary.RekeySpendingKey}},
		{plainFalconKeyType, noBounds, false, true, []string{boundary.RekeyRefused, boundary.RekeySpendingKey}},
		{plainFalconKeyType, noBounds, true, false, []string{boundary.RekeyOnlyThese}},
		{plainFalconKeyType, noBounds, true, true, []string{boundary.RekeyOnlyThese, boundary.RekeyPlusCosigned}},
		{plainEd25519KeyType, noBounds, true, true, []string{boundary.RekeyOnlyThese, boundary.RekeyPlusCosigned}},
		// Bounds take every rekey setting too (ninth amendment).
		{boundedHostKeyType, 0, false, false, []string{boundary.RekeyRefused, boundary.RekeySpendingKey}},
		{boundedHostKeyType, 0, false, true, []string{boundary.RekeyRefused, boundary.RekeySpendingKey}},
		{boundedHostKeyType, 0, true, false, []string{boundary.RekeyOnlyThese}},
		{boundedHostKeyType, 0, true, true, []string{boundary.RekeyOnlyThese, boundary.RekeyPlusCosigned}},
		{plainEd25519KeyType, customBounds, true, true, []string{boundary.RekeyOnlyThese, boundary.RekeyPlusCosigned}},
	} {
		m := overlayForm(t, test.keyType, test.preset)
		if test.listed {
			m.forms.genericLSigParams[overlayList] = testAddress(1)
		}
		if test.cosigned {
			m.forms.genericLSigParams[overlayCosigner] = "WITNESS"
		}
		rekey, _ := paramNamed(m.formSpec(t).Params, overlayRekey)
		if !slices.Equal(rekey.Options, test.want) {
			t.Errorf("%s listed=%v cosigned=%v: options = %v, want %v", test.keyType, test.listed, test.cosigned, rekey.Options, test.want)
		}
		wantLabel := "Allow rekeys"
		if test.listed {
			wantLabel = "Rekey-to option"
		}
		if rekey.Label != wantLabel {
			t.Errorf("%s listed=%v: label = %q, want %q", test.keyType, test.listed, rekey.Label, wantLabel)
		}
	}
}

// What the operator chose is what is sent: empty overlays are left out, and a
// preset's own rekey setting gives way to the operator's.
func TestOverlayFormSendsTheChoices(t *testing.T) {
	overlayInventory(t)
	target, recipient := testAddress(1), testAddress(2)
	for _, test := range []struct {
		name    string
		keyType string
		preset  int
		values  map[string]string
		want    map[string]string
	}{
		{
			name: "plain, nothing chosen", keyType: plainFalconKeyType, preset: noBounds,
			values: map[string]string{},
			want:   map[string]string{overlayRekey: boundary.RekeyRefused},
		},
		{
			name: "plain, spending key alone", keyType: plainEd25519KeyType, preset: noBounds,
			values: map[string]string{overlayRekey: boundary.RekeySpendingKey},
			want:   map[string]string{overlayRekey: boundary.RekeySpendingKey},
		},
		{
			name: "plain, cosigned plus others", keyType: plainFalconKeyType, preset: noBounds,
			values: map[string]string{overlayCosigner: "WITNESS", overlayList: target, overlayRekey: boundary.RekeyPlusCosigned},
			want:   map[string]string{overlayCosigner: "WITNESS", overlayList: target, overlayRekey: boundary.RekeyPlusCosigned},
		},
		{
			name: "allowlist with a list", keyType: boundedHostKeyType, preset: 0,
			values: map[string]string{boundary.ParameterRecipients: recipient, overlayList: target, overlayRekey: boundary.RekeyOnlyThese},
			want: map[string]string{
				boundary.ParameterRecipients: recipient, overlayList: target, overlayRekey: boundary.RekeyOnlyThese,
				boundary.ParameterSpendEffects: "pay,axfer,asset_opt_in", boundary.ParameterListEncoding: boundary.EncodingAuto,
			},
		},
		{
			name: "an unoffered choice falls back to the first, no rekeys", keyType: boundedHostKeyType, preset: 0,
			values: map[string]string{boundary.ParameterRecipients: recipient, overlayCosigner: "WITNESS", overlayRekey: boundary.RekeyOnlyThese},
			want: map[string]string{
				boundary.ParameterRecipients: recipient, overlayCosigner: "WITNESS", overlayRekey: boundary.RekeyRefused,
				boundary.ParameterSpendEffects: "pay,axfer,asset_opt_in", boundary.ParameterListEncoding: boundary.EncodingAuto,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := overlayForm(t, test.keyType, test.preset)
			for name, value := range test.values {
				m.forms.genericLSigParams[name] = value
			}
			m.forms.generateFocus = len(m.formSpec(t).Params)
			next, _ := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
			got := next.(Model)
			if got.viewState != ViewGenerating {
				t.Fatalf("view = %v, error = %q", got.viewState, got.forms.generateError)
			}
			if fmt.Sprint(got.forms.pendingGenerateParams) != fmt.Sprint(test.want) {
				t.Fatalf("sent %v, want %v", got.forms.pendingGenerateParams, test.want)
			}
		})
	}
}

// shownRekey is the rekey setting the control shows and the form would send.
func (m Model) shownRekey(t *testing.T) string {
	t.Helper()
	rekey, _ := paramNamed(m.formSpec(t).Params, overlayRekey)
	return shownOption(rekey, m.forms.genericLSigParams[overlayRekey])
}

// Adding or clearing the list, or removing the cosigner, moves the rekey control
// to a setting it still offers, and the operator's choice returns when it fits
// again. An optional cosigner can be removed.
func TestOverlayRekeyFollowsTheListAndTheCosigner(t *testing.T) {
	overlayInventory(t)
	m := overlayForm(t, plainFalconKeyType, noBounds)
	if got := m.shownRekey(t); got != boundary.RekeyRefused {
		t.Fatalf("initial rekey = %q, want refused", got)
	}
	m.forms.genericLSigParams[overlayCosigner] = "WITNESS"
	m = m.pressOnField(t, overlayList, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(testAddress(1))})
	if got := m.shownRekey(t); got != boundary.RekeyOnlyThese {
		t.Fatalf("with a list, rekey = %q, want only_these", got)
	}
	m = m.pressOnField(t, overlayRekey, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(">")})
	if got := m.shownRekey(t); got != boundary.RekeyPlusCosigned {
		t.Fatalf("after >, rekey = %q, want plus_cosigned", got)
	}
	m = m.pressOnField(t, overlayCosigner, tea.KeyMsg{Type: tea.KeyBackspace})
	if got := m.forms.genericLSigParams[overlayCosigner]; got != "" {
		t.Fatalf("backspace left the optional cosigner %q", got)
	}
	if got := m.shownRekey(t); got != boundary.RekeyOnlyThese {
		t.Fatalf("without the cosigner, rekey = %q, want only_these", got)
	}
	m.forms.genericLSigParams[overlayCosigner] = "WITNESS"
	if got := m.shownRekey(t); got != boundary.RekeyPlusCosigned {
		t.Fatalf("with the cosigner back, rekey = %q, want the operator's plus_cosigned", got)
	}
	m.forms.genericLSigParams[overlayList] = ""
	before := m.shownRekey(t)
	m = m.pressOnField(t, overlayRekey, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(">")})
	if got := m.shownRekey(t); got == before || !slices.Contains([]string{boundary.RekeyRefused, boundary.RekeySpendingKey}, got) {
		t.Fatalf("without a list, > moved %q to %q", before, got)
	}

	// A preset that needs a cosigner keeps it required.
	corridor := overlayForm(t, boundedHostKeyType, 2)
	corridor.forms.genericLSigParams[overlayCosigner] = "WITNESS"
	corridor = corridor.pressOnField(t, overlayCosigner, tea.KeyMsg{Type: tea.KeyBackspace})
	if got := corridor.forms.genericLSigParams[overlayCosigner]; got != "WITNESS" {
		t.Fatalf("backspace removed Corridor's required cosigner: %q", got)
	}
}

// A preset's form opens as the preset describes it: one that needs a list
// offers the list's options at once, and its fixed rekey setting is the
// initial choice. A form never starts from an earlier form's values.
func TestOverlayFormStartsAsThePresetSays(t *testing.T) {
	overlayInventory(t)
	for index, preset := range boundary.Presets() {
		m := overlayForm(t, boundedHostKeyType, index)
		if got, want := m.shownRekey(t), preset.Fixed[boundary.ParameterRekeyAuthority]; got != want {
			t.Errorf("%s: opens with rekey %q, want %q", preset.Name, got, want)
		}
		rekey, _ := paramNamed(m.formSpec(t).Params, overlayRekey)
		needsList := slices.Contains(preset.Fields, boundary.ParameterRekeyTo)
		if wantLabel := map[bool]string{true: "Rekey-to option", false: "Allow rekeys"}[needsList]; rekey.Label != wantLabel {
			t.Errorf("%s: rekey control %q, want %q", preset.Name, rekey.Label, wantLabel)
		}
	}

	m := overlayForm(t, plainFalconKeyType, noBounds)
	m.forms.genericLSigParams[overlayCosigner] = "WITNESS"
	m.forms.genericLSigParams[overlayList] = testAddress(1)
	m.forms.genericLSigParams[overlayRekey] = boundary.RekeyPlusCosigned
	m = m.initGenericLSigParamsForKeyType(plainFalconKeyType)
	if got := m.shownRekey(t); got != boundary.RekeyRefused || m.forms.genericLSigParams[overlayRekey] != boundary.RekeyRefused {
		t.Fatalf("a reopened form starts from the old one: rekey %q", m.forms.genericLSigParams[overlayRekey])
	}
}

// Every field of every overlay arrangement fits 80x24, and the screen names the
// choices in words.
func TestOverlayFormFitsAt80x24(t *testing.T) {
	overlayInventory(t)
	type arrangement struct {
		cosigned, listed bool
	}
	seen := map[string]bool{}
	for _, form := range []struct {
		keyType string
		preset  int
	}{
		{plainFalconKeyType, noBounds}, {plainEd25519KeyType, noBounds},
		{boundedHostKeyType, 0}, {boundedHostKeyType, 1}, {boundedHostKeyType, 2}, {boundedHostKeyType, 3},
		{plainEd25519KeyType, 2}, {boundedHostKeyType, customBounds}, {plainEd25519KeyType, customBounds},
	} {
		for _, a := range []arrangement{{false, false}, {true, false}, {false, true}, {true, true}} {
			m := overlayForm(t, form.keyType, form.preset)
			// As apadmin runs: its own terminal, connected, with and without an error.
			m.standalone = true
			m.connectionState = ConnectionConnected
			if a.cosigned {
				m.forms.genericLSigParams[overlayCosigner] = "WITNESS"
			}
			if a.listed {
				m.forms.genericLSigParams[overlayList] = testAddress(1) + "\n" + testAddress(2)
			}
			if a.cosigned && a.listed {
				m.forms.genericLSigParams[overlayRekey] = boundary.RekeyPlusCosigned
			}
			spec := m.formSpec(t)
			for focus := 0; focus <= 2*len(spec.Params)+1; focus++ {
				m.forms.generateFocus = focus % (len(spec.Params) + 1)
				m.forms.generateError = ""
				if focus > len(spec.Params) {
					// The signer's longest refusal, which wraps.
					m.forms.generateError = "this signer requires new accounts to pay only listed recipients and to refuse rekeys or take only listed ones (require_contained)"
				}
				m = m.ensureParamVisible(min(m.forms.generateFocus, len(spec.Params)-1), m.getMaxVisibleParams())
				sized := sizedForTest(t, m, MinWidth, MinHeight)
				view := stripANSI(assertFitsWindow(t, sized))
				if strings.Contains(view, "Panel lines") {
					t.Fatalf("%s preset %d %+v focus %d: falls back to the panel scroller:\n%s", form.keyType, form.preset, a, focus, view)
				}
				for _, phrase := range []string{"Require a cosigner (Falcon-1024)", "Add rekey-to addresses", "Allow rekeys",
					"Rekey-to option", "No, never", "Yes, spending key alone", "Yes, spending key and cosigner",
					"Only these addresses", "These, plus others with the cosigner", "None (Enter to choose one)",
					"── Bounds ──", "── Cosigner and rekeys ──"} {
					if strings.Contains(view, phrase) {
						seen[phrase] = true
					}
				}
			}
		}
	}
	for _, phrase := range []string{"Require a cosigner (Falcon-1024)", "Add rekey-to addresses", "Allow rekeys",
		"Rekey-to option", "No, never", "Yes, spending key alone", "Yes, spending key and cosigner",
		"Only these addresses", "These, plus others with the cosigner", "None (Enter to choose one)",
		"── Bounds ──", "── Cosigner and rekeys ──"} {
		if !seen[phrase] {
			t.Errorf("no overlay form at 80x24 shows %q", phrase)
		}
	}
}

// A cosigner imported from the overlay form fills its cosigner control when the
// signer's key types come back, with or without a preset, and keeps what the
// operator had typed.
func TestImportedCosignerFillsTheOverlayForm(t *testing.T) {
	infos := overlayInventory(t)
	for _, keyType := range []string{boundedHostKeyType, plainFalconKeyType} {
		m := Model{viewState: ViewGenerateParams, cosigner: cosignerState{loaded: true}}
		index, _ := keyTypeIndex(keyType, getKeyTypeCount(), getKeyTypeByIndex)
		m.forms.generateKeyType = index
		m = m.initGenericLSigParamsForKeyType(keyType)
		m.forms.genericLSigParams[overlayList] = "typed"
		m.cosigner.pendingKeyType = keyType
		m.cosigner.pendingWitnessID = "WITNESS"

		next, _ := m.Update(KeyTypesMsg{KeyTypes: infos})
		got := next.(Model)
		if got.forms.genericLSigParams[overlayCosigner] != "WITNESS" || got.forms.genericLSigParams[overlayList] != "typed" {
			t.Fatalf("%s: cosigner = %q, list = %q", keyType, got.forms.genericLSigParams[overlayCosigner], got.forms.genericLSigParams[overlayList])
		}
		if got.cosigner.pendingWitnessID != "" {
			t.Fatalf("%s: the pending import was not consumed", keyType)
		}
	}
}

// Custom bounds leaves an optional choice unset until the operator picks one,
// so a limits-only account can be made without a
// file; and the Cosigners manager's form, which has no preset, has no bounds.
func TestCustomBoundsLeavesChoicesUnsetAndTheManagerFormHasNone(t *testing.T) {
	overlayInventory(t)
	for name, test := range map[string]struct {
		values  map[string]string
		absent  []string
		present map[string]string
	}{
		"limits-only": {
			values:  map[string]string{boundary.ParameterSpendEffects: "pay", boundary.ParameterRecipientScope: boundary.RecipientScopeAny, overlayRekey: boundary.RekeyRefused},
			absent:  []string{boundary.ParameterListEncoding, boundary.ParameterRecipients, "unlock_round"},
			present: map[string]string{boundary.ParameterRecipientScope: boundary.RecipientScopeAny},
		},
	} {
		m := overlayForm(t, plainEd25519KeyType, customBounds)
		for field, value := range test.values {
			m.forms.genericLSigParams[field] = value
		}
		spec := m.formSpec(t)
		scope, _ := paramNamed(spec.Params, boundary.ParameterRecipientScope)
		if scope.Options[0] != "" || spec.optionLabel(scope.Name, "") != "Not set" {
			t.Fatalf("%s: recipient scope offers %v", name, scope.Options)
		}
		m.forms.generateFocus = len(spec.Params)
		next, _ := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
		got := next.(Model)
		if got.viewState != ViewGenerating {
			t.Fatalf("%s: view = %v, error = %q", name, got.viewState, got.forms.generateError)
		}
		for _, field := range test.absent {
			if _, ok := got.forms.pendingGenerateParams[field]; ok {
				t.Errorf("%s: sent %s: %v", name, field, got.forms.pendingGenerateParams)
			}
		}
		for field, value := range test.present {
			if got.forms.pendingGenerateParams[field] != value {
				t.Errorf("%s: %s = %q", name, field, got.forms.pendingGenerateParams[field])
			}
		}
	}

	// The manager opens the form with a cosigner and no preset.
	m := Model{viewState: ViewGenerateParams, cosigner: cosignerState{loaded: true}}
	index, _ := keyTypeIndex(plainFalconKeyType, getKeyTypeCount(), getKeyTypeByIndex)
	m.forms.generateKeyType = index
	m = m.initGenericLSigParamsForKeyType(plainFalconKeyType)
	m.forms.genericLSigParams[overlayCosigner] = "WITNESS"
	spec := m.formSpec(t)
	if got := paramNames(spec.Params); !slices.Equal(got, []string{overlayCosigner, overlayList, overlayRekey}) {
		t.Fatalf("manager form fields = %v, want the overlays alone", got)
	}
	m.forms.generateFocus = len(spec.Params)
	next, _ := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if sent := next.(Model).forms.pendingGenerateParams; fmt.Sprint(sent) != fmt.Sprint(map[string]string{overlayCosigner: "WITNESS", overlayRekey: boundary.RekeyRefused}) {
		t.Fatalf("manager form sent %v", sent)
	}
}

// A cosigner imported from the form comes back focused and in view: at 80x24 a
// bounds preset scrolls, and a keystroke on a hidden field would act on what
// the operator can't see.
func TestImportedCosignerIsFocusedInView(t *testing.T) {
	overlayInventory(t)
	for preset := range boundary.Presets() {
		m := sizedForTest(t, overlayForm(t, boundedHostKeyType, preset), MinWidth, MinHeight)
		_, hasRecipients := m.forms.genericLSigParams[boundary.ParameterRecipients]
		if hasRecipients {
			m.forms.genericLSigParams[boundary.ParameterRecipients] = testAddress(1)
		}
		m.cosigner.pendingKeyType = boundedHostKeyType
		m.cosigner.pendingWitnessID = "WITNESS"
		m = m.resumeCosignerImport()
		focus := m.forms.genericLSigParamOrder[m.forms.generateFocus]
		if focus != overlayCosigner || m.forms.genericLSigParams[overlayCosigner] != "WITNESS" {
			t.Fatalf("preset %d: focus %q, cosigner %q", preset, focus, m.forms.genericLSigParams[overlayCosigner])
		}
		if hasRecipients && m.forms.genericLSigParams[boundary.ParameterRecipients] != testAddress(1) {
			t.Fatalf("preset %d: the typed recipients were lost", preset)
		}
		if offset := m.forms.generateParamScrollOffset; m.forms.generateFocus < offset || m.forms.generateFocus >= offset+m.getMaxVisibleParams() {
			t.Fatalf("preset %d: focus %d is outside the visible rows from %d", preset, m.forms.generateFocus, offset)
		}
		if view := stripANSI(assertFitsWindow(t, m)); !strings.Contains(view, "Require a cosigner (Falcon-1024)") {
			t.Fatalf("preset %d: the focused cosigner control is not on screen:\n%s", preset, view)
		}
	}
}
