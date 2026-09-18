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

func testSentryReferences() []SentryReferenceInfo {
	return []SentryReferenceInfo{
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

func TestKeyListSentryShortcutOpensManagerOnlyOnSigner(t *testing.T) {
	signer := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "signer"}},
	}
	nextModel, cmd := signer.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if next.viewState != ViewSentryReferences {
		t.Fatalf("signer viewState = %v, want %v", next.viewState, ViewSentryReferences)
	}
	if cmd == nil {
		t.Fatal("signer sentry manager did not request a reference refresh")
	}

	sentry := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "sentry"}},
	}
	nextModel, cmd = sentry.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next = nextModel.(Model)
	if next.viewState != ViewKeyList {
		t.Fatalf("sentry viewState = %v, want %v", next.viewState, ViewKeyList)
	}
	if cmd != nil {
		t.Fatal("sentry node unexpectedly requested signer reference data")
	}
	if !strings.Contains(next.lastError, "managed on signer nodes") {
		t.Fatalf("sentry error = %q", next.lastError)
	}
}

func TestSentryManagerSortsAliasesAndKeepsPublicKeyOutOfViews(t *testing.T) {
	m := Model{
		width:  120,
		height: 30,
		sentry: sentryState{references: testSentryReferences()},
	}

	references := m.sortedSentryReferences()
	if got := []string{references[0].Name, references[1].Name, references[2].Name}; strings.Join(got, ",") != "alpha,east,west" {
		t.Fatalf("sorted aliases = %v", got)
	}

	list := stripANSI(m.renderSentryReferences())
	if !strings.Contains(list, "alpha") || !strings.Contains(list, "east") || !strings.Contains(list, "west") {
		t.Fatalf("manager list missing aliases:\n%s", list)
	}
	if strings.Contains(list, "deadbeefcafebabe") || strings.Contains(list, testWitnessKeyID) {
		t.Fatalf("manager list exposed raw public material or an unabridged ID:\n%s", list)
	}

	m.sentry.managerSelected = 2
	details := stripANSI(m.renderSentryReferenceDetails())
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

func TestSentryManagerRemovalDefaultsToCancelAndReportsResult(t *testing.T) {
	m := Model{
		viewState: ViewSentryReferenceDetails,
		sentry: sentryState{
			references:      testSentryReferences(),
			managerSelected: 2,
		},
	}

	nextModel, _ := m.handleSentryReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	next := nextModel.(Model)
	if next.viewState != ViewSentryRemoveConfirm || next.sentry.removeFocus != 0 {
		t.Fatalf("remove confirmation = view %v focus %d", next.viewState, next.sentry.removeFocus)
	}

	nextModel, cmd := next.handleSentryRemoveConfirmKeys(tea.KeyMsg{Type: tea.KeyEnter})
	next = nextModel.(Model)
	if next.viewState != ViewSentryReferenceDetails || cmd != nil {
		t.Fatalf("default confirmation did not cancel: view %v cmd nil=%v", next.viewState, cmd == nil)
	}

	next.viewState = ViewSentryRemoveConfirm
	nextModel, cmd = next.handleSentryRemoveConfirmKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	next = nextModel.(Model)
	if next.viewState != ViewSentryRemoving || cmd == nil {
		t.Fatalf("explicit removal = view %v cmd nil=%v", next.viewState, cmd == nil)
	}

	nextModel, _ = next.Update(SentryRemoveResultMsg{Success: true, Name: "west", Removed: true})
	next = nextModel.(Model)
	if next.viewState != ViewSentryReferences || next.sentry.managerStatus != "Removed west" {
		t.Fatalf("removal result = view %v status %q", next.viewState, next.sentry.managerStatus)
	}
}

func TestManagerSentryImportReturnsToManager(t *testing.T) {
	m := Model{
		viewState: ViewSentryImporting,
		sentry: sentryState{
			returnView:   ViewSentryReferences,
			envelopeJSON: "sensitive public envelope",
		},
	}
	nextModel, _ := m.Update(SentryImportResultMsg{
		Success: true,
		Reference: SentryReferenceInfo{
			Name:         "west",
			ComponentKey: testWitnessKeyID,
		},
	})
	next := nextModel.(Model)
	if next.viewState != ViewSentryReferences {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewSentryReferences)
	}
	if next.sentry.pendingWitnessID != "" || next.sentry.pendingKeyType != "" {
		t.Fatal("manager import incorrectly queued guarded-key generation")
	}
	if next.sentry.envelopeJSON != "" {
		t.Fatal("manager import retained the public envelope")
	}
}

func TestSentryImportSuggestsSanitizedFilenameStem(t *testing.T) {
	m := Model{sentry: sentryState{
		importPath:  "/operator/exports/Lab Sentry #1.aplane-sentry.json",
		importFocus: 0,
	}}
	nextModel, _ := m.handleSentryImportFormKeys(tea.KeyMsg{Type: tea.KeyTab})
	next := nextModel.(Model)
	if next.sentry.importName != "lab-sentry-1" {
		t.Fatalf("suggested name = %q", next.sentry.importName)
	}
	if next.sentry.importFocus != 1 {
		t.Fatalf("import focus = %d, want 1", next.sentry.importFocus)
	}
}

func TestGenerateAccountFromReferencePreselectsSentry(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{
		{
			KeyType:                "ordinary.v1",
			SentryComponentKeyType: "",
		},
		{
			KeyType:                "guarded.v1",
			DisplayName:            "Guarded",
			SentryComponentKeyType: "witness.v1",
			CreationParams: []protocol.TemplateParamInfo{
				{Name: "sentry", Label: "Sentry", Type: "select", Required: true},
				{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true},
			},
		},
	})
	m := Model{
		viewState: ViewSentryReferenceDetails,
		sentry: sentryState{references: []SentryReferenceInfo{{
			Name: "lab", ComponentKey: testWitnessID1, KeyType: "witness.v1",
		}}},
	}

	nextModel, cmd := m.handleSentryReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	next := nextModel.(Model)
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	if next.viewState != ViewGenerateParams {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewGenerateParams)
	}
	if next.forms.generateKeyType != 1 || next.forms.genericLSigParams["sentry"] != testWitnessID1 {
		t.Fatalf("generation selection = index %d params %#v", next.forms.generateKeyType, next.forms.genericLSigParams)
	}
	if !next.sentry.generateFromManager {
		t.Fatal("manager generation continuation was not recorded")
	}

	nextModel, _ = next.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEsc})
	next = nextModel.(Model)
	if next.viewState != ViewSentryReferenceDetails || next.sentry.generateFromManager {
		t.Fatalf("cancel = view %v continuation %v", next.viewState, next.sentry.generateFromManager)
	}
}

func TestGenerateAccountFromReferenceChoosesAmongCompatibleTypes(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{
		{
			KeyType:                "guarded-one.v1",
			SentryComponentKeyType: "witness.v1",
			CreationParams:         []protocol.TemplateParamInfo{{Name: "sentry", Type: "select"}},
		},
		{KeyType: "wrong.v1", SentryComponentKeyType: "witness.v2"},
		{
			KeyType:                "guarded-two.v1",
			SentryComponentKeyType: "witness.v1",
			CreationParams:         []protocol.TemplateParamInfo{{Name: "sentry", Type: "select"}},
		},
	})
	m := Model{
		viewState: ViewSentryReferenceDetails,
		sentry: sentryState{references: []SentryReferenceInfo{{
			Name: "lab", ComponentKey: testWitnessID1, KeyType: "witness.v1",
		}}},
	}

	nextModel, _ := m.beginSelectedSentryGeneration()
	next := nextModel.(Model)
	if next.viewState != ViewSentryGenerateType {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewSentryGenerateType)
	}
	if got := next.sentry.generateTypeIndices; len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("compatible indices = %v", got)
	}

	nextModel, _ = next.handleSentryGenerateTypeKeys(tea.KeyMsg{Type: tea.KeyDown})
	next = nextModel.(Model)
	nextModel, _ = next.handleSentryGenerateTypeKeys(tea.KeyMsg{Type: tea.KeyEnter})
	next = nextModel.(Model)
	if next.viewState != ViewGenerateParams || next.forms.generateKeyType != 2 {
		t.Fatalf("selected generation = view %v index %d", next.viewState, next.forms.generateKeyType)
	}
	if next.forms.genericLSigParams["sentry"] != testWitnessID1 {
		t.Fatalf("sentry selector = %q", next.forms.genericLSigParams["sentry"])
	}
}

func TestSentryDetailsHaveNoClientRouteActions(t *testing.T) {
	t.Setenv("APCLIENT_DATA", t.TempDir())
	m := Model{width: 120, height: 40, viewState: ViewSentryReferenceDetails, sentry: sentryState{references: testSentryReferences()}}
	view := m.renderSentryReferenceDetails()
	for _, label := range []string{"Client routes", "Live route", "Verify route"} {
		if strings.Contains(view, label) {
			t.Fatalf("details expose client routing: %s", label)
		}
	}
	next, cmd := m.handleSentryReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if cmd != nil || next.(Model).viewState != ViewSentryReferenceDetails {
		t.Fatal("v still starts route verification")
	}
}
