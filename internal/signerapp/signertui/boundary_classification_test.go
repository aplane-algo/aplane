// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/protocol"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
)

const validBoundaryForTUI = "schema: aplane.boundary.v1\nspend: [pay]\nrecipients: [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ]\nrekey: {authority: spending_key}\n"

// secondPerKeyType stands for a per-key type this build knows nothing about. It's
// a cache of server data here, so no provider or registry backs it.
const secondPerKeyType = "example.second-bounded.v1"

func withInventory(t *testing.T, infos ...protocol.KeyTypeInfo) {
	t.Helper()
	setServerKeyTypes(infos)
	t.Cleanup(func() { setServerKeyTypes(nil) })
}

func pressEnterOnGenerateForm(t *testing.T, index int) (Model, tea.Cmd) {
	t.Helper()
	m := Model{viewState: ViewGenerateForm, width: 80, height: 24, forms: formsState{generateKeyType: index, generateFocus: 0}}
	next, cmd := m.handleGenerateFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	return next.(Model), cmd
}

func TestPerKeyInventoryRoutesAnyTypeToPresets(t *testing.T) {
	for _, keyType := range []string{boundary.KeyTypeV1, secondPerKeyType} {
		withInventory(t, protocol.KeyTypeInfo{KeyType: keyType, PerKeyContract: true})
		got, _ := pressEnterOnGenerateForm(t, 0)
		if got.viewState != ViewBoundaryPreset || got.forms.boundaryKeyType != keyType {
			t.Fatalf("%s: view = %v, classified = %q", keyType, got.viewState, got.forms.boundaryKeyType)
		}
	}
}

// The name proves nothing: only the signer's answer picks the flow.
func TestKnownBoundedNameWithoutTheFieldIsNotPerKey(t *testing.T) {
	withInventory(t, protocol.KeyTypeInfo{KeyType: boundary.KeyTypeV1})
	got, _ := pressEnterOnGenerateForm(t, 0)
	if got.viewState == ViewBoundaryPreset || got.forms.boundaryKeyType != "" {
		t.Fatalf("view = %v, classified = %q", got.viewState, got.forms.boundaryKeyType)
	}
}

// The compiled list stands in until inventory arrives, so a bounded type can be
// selected unclassified. Falling through would open the plain form for it.
func TestMissingInventoryIsNotAnOrdinaryType(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	useRegistryKeyTypes(t)
	types := generateKeyTypeIDs()
	if len(types) == 0 {
		t.Fatal("no compiled key types")
	}
	for index := range types {
		got, cmd := pressEnterOnGenerateForm(t, index)
		if got.viewState != ViewGenerateForm {
			t.Fatalf("%s: view = %v", types[index], got.viewState)
		}
		if !strings.Contains(got.forms.generateError, "have not loaded") {
			t.Fatalf("%s: error = %q", types[index], got.forms.generateError)
		}
		if cmd == nil {
			t.Fatalf("%s: no reload was requested", types[index])
		}
	}
}

func TestPresetAppliesOnlyToTheClassifiedType(t *testing.T) {
	boundedaccount.RegisterClient()
	useRegistryKeyTypes(t)
	preset := boundary.Presets()[0]
	classified := Model{forms: formsState{boundaryKeyType: boundary.KeyTypeV1, boundaryPreset: &preset}}
	if spec := classified.paramSpecFor(boundary.KeyTypeV1); spec == nil || spec.DisplayName != preset.Title {
		t.Fatalf("classified type did not get the preset: %+v", spec)
	}
	other := Model{forms: formsState{boundaryKeyType: secondPerKeyType, boundaryPreset: &preset}}
	if spec := other.paramSpecFor(boundary.KeyTypeV1); spec == nil || spec.DisplayName == preset.Title {
		t.Fatalf("the preset applied to a type it was not selected for: %+v", spec)
	}
}

func TestPresetValuesReachOnlyTheClassifiedType(t *testing.T) {
	boundedaccount.RegisterClient()
	useRegistryKeyTypes(t)
	preset := boundary.Presets()[0]
	m := Model{viewState: ViewGenerateParams, forms: formsState{boundaryKeyType: secondPerKeyType, boundaryPreset: &preset}}
	m.forms.genericLSigParams = map[string]string{}
	got, _, errText := m.submitParamModal(boundary.KeyTypeV1, &paramSpec{Validate: func(map[string]string) error { return nil }}, ViewGenerating,
		func(string, map[string]string, string) tea.Cmd { return nil })
	if errText != "" {
		t.Fatal(errText)
	}
	if got.forms.pendingGenerateParams == nil {
		t.Fatal("submitParamModal() did not reach the merge")
	}
	if _, merged := got.forms.pendingGenerateParams[boundary.ParameterRekeyAuthority]; merged {
		t.Fatalf("preset values reached another type: %v", got.forms.pendingGenerateParams)
	}
}

func TestChoosingAPresetOpensTheClassifiedTypesForm(t *testing.T) {
	preset := boundary.Presets()[0]
	info := protocol.KeyTypeInfo{KeyType: secondPerKeyType, PerKeyContract: true}
	for _, name := range preset.Fields {
		info.CreationParams = append(info.CreationParams, protocol.TemplateParamInfo{Name: name, Label: name, Type: "string"})
	}
	withInventory(t, info)
	m := Model{viewState: ViewBoundaryPreset, forms: formsState{boundaryKeyType: secondPerKeyType}}
	next, _ := m.handleBoundaryPresetKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewGenerateParams || !slices.Equal(got.forms.genericLSigParamOrder, preset.Fields) {
		t.Fatalf("view = %v, fields = %v", got.viewState, got.forms.genericLSigParamOrder)
	}
}

func TestBoundaryFileGoesToTheClassifiedType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(validBoundaryForTUI), 0o600); err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	client := NewAdminClient(&queueConnector{conns: []io.ReadWriteCloser{clientConn}})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()
	lines := make(chan []byte, 1)
	go func() {
		line, err := bufio.NewReader(serverConn).ReadBytes('\n')
		if err == nil {
			lines <- line
		}
	}()

	m := Model{adminClient: client, forms: formsState{boundaryKeyType: secondPerKeyType, boundaryFile: path}}
	next, cmd := m.submitBoundaryFile()
	if got := next.(Model); got.forms.generateError != "" || cmd == nil {
		t.Fatalf("error = %q", got.forms.generateError)
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		t.Fatal("submitBoundaryFile() did not return a batch")
	}
	for _, sub := range batch {
		go sub()
	}
	select {
	case line := <-lines:
		var request protocol.PrepareGenerateKeyMessage
		if err := json.Unmarshal(line, &request); err != nil {
			t.Fatal(err)
		}
		if request.KeyType != secondPerKeyType {
			t.Fatalf("request key type = %q", request.KeyType)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out reading the prepare request")
	}
}

func TestLeavingPresetsForgetsTheClassification(t *testing.T) {
	m := Model{viewState: ViewBoundaryPreset, forms: formsState{boundaryKeyType: secondPerKeyType}}
	next, _ := m.handleBoundaryPresetKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if got := next.(Model); got.forms.boundaryKeyType != "" {
		t.Fatalf("classification survived: %q", got.forms.boundaryKeyType)
	}
}
