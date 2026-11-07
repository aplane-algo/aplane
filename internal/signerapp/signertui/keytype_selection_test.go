// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/protocol"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

func generateIndexOf(t *testing.T, keyType string) int {
	t.Helper()
	index := slices.Index(generateKeyTypeIDs(), keyType)
	if index < 0 {
		t.Fatalf("%s is not in the Generate list %v", keyType, generateKeyTypeIDs())
	}
	return index
}

func receiveKeyTypes(t *testing.T, m Model, infos ...protocol.KeyTypeInfo) Model {
	t.Helper()
	t.Cleanup(func() { setServerKeyTypes(nil) })
	next, _ := m.Update(KeyTypesMsg{KeyTypes: infos})
	return next.(Model)
}

func pressGenerateKey(t *testing.T, m Model, key tea.KeyMsg) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.handleGenerateFormKeys(key)
	return next.(Model), cmd
}

// The compiled list stands in until the signer's arrives, and the signer's lists only
// enabled types, so it is usually shorter. Enter on an unclassified type asks the
// operator to try again; the second Enter must act on the type they chose, not on
// whatever the old index names in the new list.
func TestReloadedListKeepsTheChosenType(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	clientreg.RegisterClient()
	useRegistryKeyTypes(t)
	chosen := generateIndexOf(t, boundary.KeyTypeV1)

	m := Model{viewState: ViewGenerateForm, width: 80, height: 24, forms: formsState{generateKeyType: chosen}}
	m, _ = pressGenerateKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.forms.generateError != generateKeyTypesNotLoaded {
		t.Fatalf("error = %q, want the not-loaded prompt", m.forms.generateError)
	}

	// Build the signer's list so the old position names a different, valid type.
	// Other tests register types too, so the compiled position isn't fixed.
	signerList := []protocol.KeyTypeInfo{{KeyType: boundary.KeyTypeV1, PerKeyContract: true}}
	if chosen == 0 {
		signerList = append(signerList, protocol.KeyTypeInfo{KeyType: "ed25519"})
	}
	for i := 1; i <= chosen; i++ {
		signerList = append(signerList, protocol.KeyTypeInfo{KeyType: fmt.Sprintf("zz.filler-%02d.v1", i)})
	}
	m = receiveKeyTypes(t, m, signerList...)
	if at := getKeyTypeByIndex(chosen); at == "" || at == boundary.KeyTypeV1 {
		t.Fatalf("the old index names %q in the new list; this test needs it to name another type", at)
	}
	if got := getKeyTypeByIndex(m.forms.generateKeyType); got != boundary.KeyTypeV1 {
		t.Fatalf("cursor names %q after the reload, want %s", got, boundary.KeyTypeV1)
	}
	if m.forms.generateError != "" {
		t.Fatalf("error = %q after the list arrived, want it cleared", m.forms.generateError)
	}

	m, _ = pressGenerateKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewBoundaryPreset || m.forms.boundaryKeyType != boundary.KeyTypeV1 {
		t.Fatalf("view = %v, classified = %q", m.viewState, m.forms.boundaryKeyType)
	}
}

// When the new list drops the selected type, the cursor lands on some other type.
// For a type with no parameters, Enter generates at once with no review, so Enter
// must wait for the operator to choose again.
func TestDroppedTypeNeedsAFreshChoice(t *testing.T) {
	const dropped = "example.dropped.v1"
	withInventory(t,
		protocol.KeyTypeInfo{KeyType: "ed25519"},
		protocol.KeyTypeInfo{KeyType: "falcon1024"},
		protocol.KeyTypeInfo{KeyType: dropped},
	)
	m := Model{viewState: ViewGenerateForm, width: 80, height: 24, forms: formsState{generateKeyType: generateIndexOf(t, dropped)}}

	m = receiveKeyTypes(t, m, protocol.KeyTypeInfo{KeyType: "ed25519"}, protocol.KeyTypeInfo{KeyType: "falcon1024"})
	if !m.forms.generateNeedsChoice || !strings.Contains(m.forms.generateError, "not offered by the signer") {
		t.Fatalf("needs choice = %v, error = %q", m.forms.generateNeedsChoice, m.forms.generateError)
	}

	m, cmd := pressGenerateKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil || m.viewState != ViewGenerateForm || m.forms.generateError != "Choose a key type first." {
		t.Fatalf("Enter after the drop: cmd = %v, view = %v, error = %q", cmd != nil, m.viewState, m.forms.generateError)
	}

	// A cursor key is a choice even when the cursor can't move further.
	m, _ = pressGenerateKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	m, cmd = pressGenerateKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || m.viewState != ViewGenerating {
		t.Fatalf("Enter after choosing: cmd = %v, view = %v", cmd != nil, m.viewState)
	}
}

// A parameter form is built on the selected type. If the signer stops offering it,
// the form is abandoned rather than switched to another type's parameters.
func TestDroppedTypeAbandonsItsParameterForm(t *testing.T) {
	withInventory(t, protocol.KeyTypeInfo{KeyType: "ed25519"})
	m := Model{viewState: ViewGenerateParams, forms: formsState{genericLSigParams: map[string]string{"limit": "5"}}}

	m = m.reselectKeyTypes("example.gone.v1", "")
	if m.viewState != ViewGenerateForm || m.forms.genericLSigParams != nil || !m.forms.generateNeedsChoice {
		t.Fatalf("view = %v, params = %v, needs choice = %v", m.viewState, m.forms.genericLSigParams, m.forms.generateNeedsChoice)
	}
}

// The cosigner picker refreshes the list partway through the preset flow. The flow
// stays on the type it started with even if the refresh moves that type's position.
func TestPresetFlowSurvivesAReorderedList(t *testing.T) {
	boundedaccount.RegisterClient()
	withInventory(t,
		protocol.KeyTypeInfo{KeyType: "ed25519"},
		protocol.KeyTypeInfo{KeyType: boundary.KeyTypeV1, PerKeyContract: true},
	)
	start := generateIndexOf(t, boundary.KeyTypeV1)
	preset := boundary.Presets()[0]
	// The cursor is left on another type: the flow's recorded type decides, so a
	// cursor index that drifted (or was set by another view) can't redirect it.
	m := Model{viewState: ViewGenerateParams, forms: formsState{
		generateKeyType: generateIndexOf(t, "ed25519"), boundaryKeyType: boundary.KeyTypeV1, boundaryPreset: &preset,
	}}
	m = m.initGenericLSigParamsForKeyType(boundary.KeyTypeV1)
	fields := slices.Clone(m.forms.genericLSigParamOrder)

	m = receiveKeyTypes(t, m,
		protocol.KeyTypeInfo{KeyType: "aplane.aaa-earlier.v1"},
		protocol.KeyTypeInfo{KeyType: "ed25519"},
		protocol.KeyTypeInfo{KeyType: boundary.KeyTypeV1, PerKeyContract: true},
	)
	if at := getKeyTypeByIndex(start); at == boundary.KeyTypeV1 {
		t.Fatal("the refresh didn't move the type, so this test proves nothing")
	}
	if m.viewState != ViewGenerateParams {
		t.Fatalf("view = %v, want the preset's parameter form", m.viewState)
	}
	if got := getKeyTypeByIndex(m.forms.generateKeyType); got != boundary.KeyTypeV1 {
		t.Fatalf("cursor names %q, want %s", got, boundary.KeyTypeV1)
	}
	if spec := m.paramSpecFor(getKeyTypeByIndex(m.forms.generateKeyType)); spec == nil || len(spec.Params) != len(fields) {
		t.Fatalf("parameter form after the refresh = %v, want the preset's %v", spec, fields)
	}
}
