// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

const testWitnessKeyID = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"

func testCosignerReferences() []CosignerReferenceInfo {
	return []CosignerReferenceInfo{
		{
			Name:            "west",
			ComponentKey:    testWitnessKeyID,
			KeyType:         "aplane.falcon1024.v1",
			PublicKeyHex:    "deadbeefcafebabe",
			PublicKeySHA256: "0123456789abcdef",
			ImportedAt:      "2026-09-01T12:00:00Z",
		},
		{
			Name:         "alpha",
			ComponentKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			KeyType:      "aplane.falcon1024.v1",
		},
		{
			Name:         "east",
			ComponentKey: testWitnessKeyID,
			KeyType:      "aplane.falcon1024.v1",
		},
	}
}

func TestKeyListCosignerShortcutOpensManagerOnlyOnSigner(t *testing.T) {
	signer := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "signer"}},
	}
	nextModel, cmd := signer.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if next.viewState != ViewCosignerReferences {
		t.Fatalf("signer viewState = %v, want %v", next.viewState, ViewCosignerReferences)
	}
	if cmd == nil {
		t.Fatal("signer cosigner manager did not request a reference refresh")
	}

	cosigner := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}},
	}
	nextModel, cmd = cosigner.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next = nextModel.(Model)
	if next.viewState != ViewKeyList {
		t.Fatalf("cosigner viewState = %v, want %v", next.viewState, ViewKeyList)
	}
	if cmd != nil {
		t.Fatal("cosigner node unexpectedly requested signer reference data")
	}
	if next.lastError != "" {
		t.Fatalf("cosigner error = %q, want none", next.lastError)
	}
}

func TestCosignerManagerSortsAliasesAndKeepsPublicKeyOutOfViews(t *testing.T) {
	m := Model{
		width:    120,
		height:   30,
		cosigner: cosignerState{references: testCosignerReferences()},
	}

	references := m.sortedCosignerReferences()
	if got := []string{references[0].Name, references[1].Name, references[2].Name}; strings.Join(got, ",") != "alpha,east,west" {
		t.Fatalf("sorted aliases = %v", got)
	}

	list := stripANSI(m.renderCosignerReferences())
	if !strings.Contains(list, "alpha") || !strings.Contains(list, "east") || !strings.Contains(list, "west") {
		t.Fatalf("manager list missing aliases:\n%s", list)
	}
	if strings.Contains(list, "deadbeefcafebabe") || strings.Contains(list, testWitnessKeyID) {
		t.Fatalf("manager list exposed raw public material or an unabridged ID:\n%s", list)
	}

	m.cosigner.managerSelected = 2
	details := stripANSI(m.renderCosignerReferenceDetails())
	if !strings.Contains(details, groupedWitnessKeyID(testWitnessKeyID)) {
		t.Fatalf("details missing full grouped witness ID:\n%s", details)
	}
	if !strings.Contains(details, "Aliases:  east, west") {
		t.Fatalf("details missing aliases for shared authority:\n%s", details)
	}
	if strings.Contains(details, "deadbeefcafebabe") {
		t.Fatalf("details exposed raw public key:\n%s", details)
	}
}

func TestCosignerManagerRemovalDefaultsToCancelAndReportsResult(t *testing.T) {
	m := Model{
		viewState: ViewCosignerReferenceDetails,
		cosigner: cosignerState{
			references:      testCosignerReferences(),
			managerSelected: 2,
		},
	}

	nextModel, _ := m.handleCosignerReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	next := nextModel.(Model)
	if next.viewState != ViewCosignerRemoveConfirm || next.cosigner.removeFocus != 0 {
		t.Fatalf("remove confirmation = view %v focus %d", next.viewState, next.cosigner.removeFocus)
	}

	nextModel, cmd := next.handleCosignerRemoveConfirmKeys(tea.KeyMsg{Type: tea.KeyEnter})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerReferenceDetails || cmd != nil {
		t.Fatalf("default confirmation did not cancel: view %v cmd nil=%v", next.viewState, cmd == nil)
	}

	next.viewState = ViewCosignerRemoveConfirm
	nextModel, cmd = next.handleCosignerRemoveConfirmKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerRemoving || cmd == nil {
		t.Fatalf("explicit removal = view %v cmd nil=%v", next.viewState, cmd == nil)
	}

	nextModel, _ = next.Update(CosignerRemoveResultMsg{Success: true, Name: "west", Removed: true})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerReferences || next.cosigner.managerStatus != "Removed west" {
		t.Fatalf("removal result = view %v status %q", next.viewState, next.cosigner.managerStatus)
	}
}

func TestManagerCosignerImportReturnsToManager(t *testing.T) {
	m := Model{
		viewState: ViewCosignerImporting,
		cosigner: cosignerState{
			returnView:   ViewCosignerReferences,
			envelopeJSON: "sensitive public envelope",
		},
	}
	nextModel, _ := m.Update(CosignerImportResultMsg{
		Success: true,
		Reference: CosignerReferenceInfo{
			Name:         "west",
			ComponentKey: testWitnessKeyID,
		},
	})
	next := nextModel.(Model)
	if next.viewState != ViewCosignerReferences {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewCosignerReferences)
	}
	if next.cosigner.pendingWitnessID != "" || next.cosigner.pendingKeyType != "" {
		t.Fatal("manager import incorrectly queued guarded-key generation")
	}
	if next.cosigner.envelopeJSON != "" {
		t.Fatal("manager import retained the public envelope")
	}
}

func TestCosignerImportSuggestsSanitizedFilenameStem(t *testing.T) {
	m := Model{cosigner: cosignerState{
		importPath:  "/operator/exports/Lab Cosigner #1.aplane-cosigner.json",
		importFocus: 0,
	}}
	nextModel, _ := m.handleCosignerImportFormKeys(tea.KeyMsg{Type: tea.KeyTab})
	next := nextModel.(Model)
	if next.cosigner.importName != "lab-cosigner-1" {
		t.Fatalf("suggested name = %q", next.cosigner.importName)
	}
	if next.cosigner.importFocus != 1 {
		t.Fatalf("import focus = %d, want 1", next.cosigner.importFocus)
	}
}

func TestGenerateAccountFromReferencePreselectsCosigner(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{
		{
			KeyType:                  "ordinary.v1",
			CosignerComponentKeyType: "",
		},
		{
			KeyType:                  "guarded.v1",
			DisplayName:              "Guarded",
			CosignerComponentKeyType: "witness.v1",
			CreationParams: []protocol.TemplateParamInfo{
				{Name: "cosigner", Label: "Cosigner", Type: "select", Required: true},
				{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true},
			},
		},
	})
	m := Model{
		viewState: ViewCosignerReferenceDetails,
		cosigner: cosignerState{references: []CosignerReferenceInfo{{
			Name: "lab", ComponentKey: testWitnessID1, KeyType: "witness.v1",
		}}},
	}

	nextModel, cmd := m.handleCosignerReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	next := nextModel.(Model)
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	if next.viewState != ViewGenerateParams {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewGenerateParams)
	}
	if next.forms.generateKeyType != 1 || next.forms.genericLSigParams["cosigner"] != testWitnessID1 {
		t.Fatalf("generation selection = index %d params %#v", next.forms.generateKeyType, next.forms.genericLSigParams)
	}
	if !next.cosigner.generateFromManager {
		t.Fatal("manager generation continuation was not recorded")
	}

	nextModel, _ = next.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEsc})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerReferenceDetails || next.cosigner.generateFromManager {
		t.Fatalf("cancel = view %v continuation %v", next.viewState, next.cosigner.generateFromManager)
	}
}

func TestGenerateAccountFromReferenceChoosesAmongCompatibleTypes(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{
		{
			KeyType:                  "guarded-one.v1",
			CosignerComponentKeyType: "witness.v1",
			CreationParams:           []protocol.TemplateParamInfo{{Name: "cosigner", Type: "select"}},
		},
		{KeyType: "wrong.v1", CosignerComponentKeyType: "witness.v2"},
		{
			KeyType:                  "guarded-two.v1",
			CosignerComponentKeyType: "witness.v1",
			CreationParams:           []protocol.TemplateParamInfo{{Name: "cosigner", Type: "select"}},
		},
	})
	m := Model{
		viewState: ViewCosignerReferenceDetails,
		cosigner: cosignerState{references: []CosignerReferenceInfo{{
			Name: "lab", ComponentKey: testWitnessID1, KeyType: "witness.v1",
		}}},
	}

	nextModel, _ := m.beginSelectedCosignerGeneration()
	next := nextModel.(Model)
	if next.viewState != ViewCosignerGenerateType {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewCosignerGenerateType)
	}
	if got := next.cosigner.generateTypeIndices; len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("compatible indices = %v", got)
	}

	nextModel, _ = next.handleCosignerGenerateTypeKeys(tea.KeyMsg{Type: tea.KeyDown})
	next = nextModel.(Model)
	nextModel, _ = next.handleCosignerGenerateTypeKeys(tea.KeyMsg{Type: tea.KeyEnter})
	next = nextModel.(Model)
	if next.viewState != ViewGenerateParams || next.forms.generateKeyType != 2 {
		t.Fatalf("selected generation = view %v index %d", next.viewState, next.forms.generateKeyType)
	}
	if next.forms.genericLSigParams["cosigner"] != testWitnessID1 {
		t.Fatalf("cosigner selector = %q", next.forms.genericLSigParams["cosigner"])
	}
}

func TestCosignerDetailsHaveNoClientRouteActions(t *testing.T) {
	t.Setenv("APCLIENT_DATA", t.TempDir())
	m := Model{width: 120, height: 40, viewState: ViewCosignerReferenceDetails, cosigner: cosignerState{references: testCosignerReferences()}}
	view := m.renderCosignerReferenceDetails()
	for _, label := range []string{"Client routes", "Live route", "Verify route"} {
		if strings.Contains(view, label) {
			t.Fatalf("details expose client routing: %s", label)
		}
	}
	next, cmd := m.handleCosignerReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if cmd != nil || next.(Model).viewState != ViewCosignerReferenceDetails {
		t.Fatal("v still starts route verification")
	}
}
