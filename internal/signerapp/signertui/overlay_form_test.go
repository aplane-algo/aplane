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
)

// overlayInventory reports the overlay types as the signer does, with the
// providers' own parameters, so the form is built from what production declares.
func overlayInventory(t *testing.T) {
	t.Helper()
	clientreg.RegisterClient()
	var infos []protocol.KeyTypeInfo
	for _, keyType := range []string{plainFalconKeyType, plainEd25519KeyType, boundary.KeyTypeV1} {
		provider := lsigprovider.Get(keyType)
		if provider == nil {
			t.Fatalf("%s is not registered", keyType)
		}
		info := protocol.KeyTypeInfo{
			KeyType:                  keyType,
			DisplayName:              provider.DisplayName(),
			CosignerComponentKeyType: witness.Falcon1024V1,
			PerKeyContract:           true,
		}
		if keyType == boundary.KeyTypeV1 {
			info.BoundarySchema = boundary.SchemaV1
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
}

func testAddress(seed byte) string {
	return types.Address{seed, 0x11, 0x22}.String()
}

// overlayForm opens Generate's form for keyType, through presetIndex on the
// general type (-1 for none), as Enter on the key type list and the preset
// screen does.
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
	if presetIndex >= 0 {
		if m.viewState != ViewBoundaryPreset {
			t.Fatalf("%s: view = %v, want the preset screen", keyType, m.viewState)
		}
		m.forms.boundaryPresetIndex = presetIndex
		next, _ = m.handleBoundaryPresetKeys(tea.KeyMsg{Type: tea.KeyEnter})
		m = next.(Model)
	}
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
		{plainFalconKeyType, -1, nil},
		{plainEd25519KeyType, -1, nil},
		{boundary.KeyTypeV1, 0, []string{boundary.ParameterRecipients}},
		{boundary.KeyTypeV1, 2, []string{boundary.ParameterRecipients}},
		{boundary.KeyTypeV1, 3, []string{boundary.ParameterUnlockRound}},
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
		{plainFalconKeyType, -1, false, false, []string{boundary.RekeyRefused, boundary.RekeySpendingKey}},
		{plainFalconKeyType, -1, false, true, []string{boundary.RekeyRefused, boundary.RekeySpendingKey}},
		{plainFalconKeyType, -1, true, false, []string{boundary.RekeyOnlyThese}},
		{plainFalconKeyType, -1, true, true, []string{boundary.RekeyOnlyThese, boundary.RekeyPlusCosigned}},
		{plainEd25519KeyType, -1, true, true, []string{boundary.RekeyOnlyThese, boundary.RekeyPlusCosigned}},
		{boundary.KeyTypeV1, 0, false, false, []string{boundary.RekeySpendingKey}},
		{boundary.KeyTypeV1, 0, false, true, []string{boundary.RekeySpendingKey}},
		{boundary.KeyTypeV1, 0, true, false, []string{boundary.RekeyOnlyThese}},
		{boundary.KeyTypeV1, 0, true, true, []string{boundary.RekeyOnlyThese, boundary.RekeyPlusCosigned}},
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
			name: "plain, nothing chosen", keyType: plainFalconKeyType, preset: -1,
			values: map[string]string{},
			want:   map[string]string{overlayRekey: boundary.RekeyRefused},
		},
		{
			name: "plain, spending key alone", keyType: plainEd25519KeyType, preset: -1,
			values: map[string]string{overlayRekey: boundary.RekeySpendingKey},
			want:   map[string]string{overlayRekey: boundary.RekeySpendingKey},
		},
		{
			name: "plain, cosigned plus others", keyType: plainFalconKeyType, preset: -1,
			values: map[string]string{overlayCosigner: "WITNESS", overlayList: target, overlayRekey: boundary.RekeyPlusCosigned},
			want:   map[string]string{overlayCosigner: "WITNESS", overlayList: target, overlayRekey: boundary.RekeyPlusCosigned},
		},
		{
			name: "allowlist with a list", keyType: boundary.KeyTypeV1, preset: 0,
			values: map[string]string{boundary.ParameterRecipients: recipient, overlayList: target, overlayRekey: boundary.RekeyOnlyThese},
			want: map[string]string{
				boundary.ParameterRecipients: recipient, overlayList: target, overlayRekey: boundary.RekeyOnlyThese,
				boundary.ParameterSpendEffects: "pay,axfer,asset_opt_in", boundary.ParameterListEncoding: boundary.EncodingAuto,
			},
		},
		{
			name: "corridor without a list falls back to the spending key", keyType: boundary.KeyTypeV1, preset: 0,
			values: map[string]string{boundary.ParameterRecipients: recipient, overlayCosigner: "WITNESS", overlayRekey: boundary.RekeyOnlyThese},
			want: map[string]string{
				boundary.ParameterRecipients: recipient, overlayCosigner: "WITNESS", overlayRekey: boundary.RekeySpendingKey,
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

// Adding or clearing the list, or removing the cosigner, moves the rekey control
// to a setting it still offers, and an optional cosigner can be removed.
func TestOverlayRekeyFollowsTheListAndTheCosigner(t *testing.T) {
	overlayInventory(t)
	m := overlayForm(t, plainFalconKeyType, -1)
	if got := m.forms.genericLSigParams[overlayRekey]; got != boundary.RekeyRefused {
		t.Fatalf("initial rekey = %q, want refused", got)
	}
	m.forms.genericLSigParams[overlayCosigner] = "WITNESS"
	m = m.pressOnField(t, overlayList, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(testAddress(1))})
	if got := m.forms.genericLSigParams[overlayRekey]; got != boundary.RekeyOnlyThese {
		t.Fatalf("with a list, rekey = %q, want only_these", got)
	}
	m = m.pressOnField(t, overlayRekey, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(">")})
	if got := m.forms.genericLSigParams[overlayRekey]; got != boundary.RekeyPlusCosigned {
		t.Fatalf("after >, rekey = %q, want plus_cosigned", got)
	}
	m = m.pressOnField(t, overlayCosigner, tea.KeyMsg{Type: tea.KeyBackspace})
	if got := m.forms.genericLSigParams[overlayCosigner]; got != "" {
		t.Fatalf("backspace left the optional cosigner %q", got)
	}
	if got := m.forms.genericLSigParams[overlayRekey]; got != boundary.RekeyOnlyThese {
		t.Fatalf("without the cosigner, rekey = %q, want only_these", got)
	}
	m.forms.genericLSigParams[overlayList] = ""
	m = m.pressOnField(t, overlayRekey, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(">")})
	if got := m.forms.genericLSigParams[overlayRekey]; !slices.Contains([]string{boundary.RekeyRefused, boundary.RekeySpendingKey}, got) {
		t.Fatalf("without a list, rekey = %q", got)
	}

	// A preset that needs a cosigner keeps it required.
	corridor := overlayForm(t, boundary.KeyTypeV1, 2)
	corridor.forms.genericLSigParams[overlayCosigner] = "WITNESS"
	corridor = corridor.pressOnField(t, overlayCosigner, tea.KeyMsg{Type: tea.KeyBackspace})
	if got := corridor.forms.genericLSigParams[overlayCosigner]; got != "WITNESS" {
		t.Fatalf("backspace removed Corridor's required cosigner: %q", got)
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
		{plainFalconKeyType, -1}, {plainEd25519KeyType, -1},
		{boundary.KeyTypeV1, 0}, {boundary.KeyTypeV1, 1}, {boundary.KeyTypeV1, 2}, {boundary.KeyTypeV1, 3},
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
			m = m.normalizeOverlayChoices(m.generateSelection())
			spec := m.formSpec(t)
			for focus := 0; focus <= 2*len(spec.Params)+1; focus++ {
				m.forms.generateFocus = focus % (len(spec.Params) + 1)
				m.forms.generateError = ""
				if focus > len(spec.Params) {
					m.forms.generateError = "rekey_to: invalid address \"x\": enter a full account address"
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
