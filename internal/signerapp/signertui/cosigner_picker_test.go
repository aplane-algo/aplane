// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

const (
	testWitnessID1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testWitnessID2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func TestCompatibleCosignerChoicesGroupsAliasesAndFiltersKeyType(t *testing.T) {
	m := Model{cosigner: cosignerState{references: []CosignerReferenceInfo{
		{Name: "z-backup", ComponentKey: testWitnessID1, KeyType: "witness.v1"},
		{Name: "Alpha", ComponentKey: testWitnessID1, KeyType: "witness.v1"},
		{Name: "other", ComponentKey: testWitnessID2, KeyType: "witness.v2"},
	}}}

	choices := m.compatibleCosignerChoices("witness.v1")
	if len(choices) != 1 {
		t.Fatalf("choices = %#v, want one grouped authority", choices)
	}
	if choices[0].PrimaryAlias != "Alpha" {
		t.Fatalf("primary alias = %q, want Alpha", choices[0].PrimaryAlias)
	}
	if got := strings.Join(choices[0].Aliases, ","); got != "Alpha,z-backup" {
		t.Fatalf("aliases = %q, want deterministic lexical order", got)
	}
}

func TestCosignerParamHasNoSilentDefaultWithMultipleAuthorities(t *testing.T) {
	param := protocol.TemplateParamInfo{
		Name:    "cosigner",
		Type:    "select",
		Options: []string{testWitnessID1, testWitnessID2},
		Default: testWitnessID1,
	}
	def := protocolParamInfosToDefs([]protocol.TemplateParamInfo{param})[0]
	if got := defaultParamValue(def); got != "" {
		t.Fatalf("defaultParamValue() = %q, want no implicit cosigner choice", got)
	}

	param.Options = param.Options[:1]
	def = protocolParamInfosToDefs([]protocol.TemplateParamInfo{param})[0]
	if got := defaultParamValue(def); got != testWitnessID1 {
		t.Fatalf("sole defaultParamValue() = %q, want %q", got, testWitnessID1)
	}
}

func TestEmptyCosignerSelectionUsesFriendlyValidationMessage(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                  "guarded.v1",
		DisplayName:              "Guarded",
		CosignerComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "cosigner", Label: "Cosigner", Type: "select", Required: true,
			Options: []string{testWitnessID1, testWitnessID2},
		}},
	}})
	m := Model{
		viewState: ViewGenerateParams,
		forms: formsState{
			generateKeyType:       0,
			generateFocus:         1,
			genericLSigParams:     map[string]string{"cosigner": ""},
			genericLSigParamOrder: []string{"cosigner"},
		},
		cosigner: cosignerState{loaded: true},
	}

	next, cmd := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	got := next.(Model)
	if got.viewState != ViewGenerateParams {
		t.Fatalf("viewState = %v, want %v", got.viewState, ViewGenerateParams)
	}
	if got.forms.generateError != "Choose a cosigner before continuing" {
		t.Fatalf("generateError = %q", got.forms.generateError)
	}
}

func TestGenerateCosignerParamOpensFriendlyPickerAndSubmitsWitnessID(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                  "guarded.v1",
		DisplayName:              "Guarded",
		CosignerComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "cosigner", Type: "select", Required: true,
			Options: []string{testWitnessID1, testWitnessID2}, Default: testWitnessID1,
		}},
	}})
	m := Model{
		viewState: ViewGenerateParams,
		forms: formsState{
			generateKeyType:       0,
			generateFocus:         0,
			genericLSigParams:     map[string]string{"cosigner": ""},
			genericLSigParamOrder: []string{"cosigner"},
		},
		cosigner: cosignerState{loaded: true, references: []CosignerReferenceInfo{
			{Name: "second", ComponentKey: testWitnessID2, KeyType: "witness.v1"},
			{Name: "first", ComponentKey: testWitnessID1, KeyType: "witness.v1"},
		}},
	}

	next, cmd := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("open picker command = %v, want nil", cmd)
	}
	m = next.(Model)
	if m.viewState != ViewCosignerPicker {
		t.Fatalf("viewState = %v, want ViewCosignerPicker", m.viewState)
	}
	if m.cosigner.choices[0].PrimaryAlias != "first" {
		t.Fatalf("first choice = %#v, want alias-sorted picker", m.cosigner.choices[0])
	}

	next, _ = m.handleCosignerPickerKeys(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(Model)
	next, _ = m.handleCosignerPickerKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if got := m.forms.genericLSigParams["cosigner"]; got != testWitnessID2 {
		t.Fatalf("submitted cosigner = %q, want canonical Witness Key ID", got)
	}
}

func TestRawCosignerPublicKeyInputStartsEnrollmentWhenNoReferenceExists(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                  "guarded.v1",
		DisplayName:              "Guarded",
		CosignerComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "cosigner_public_key", Type: "bytes", Required: true, MaxLength: 64,
		}},
	}})
	m := Model{
		viewState: ViewGenerateParams,
		forms: formsState{
			generateKeyType:       0,
			generateFocus:         0,
			genericLSigParams:     map[string]string{"cosigner_public_key": ""},
			genericLSigParamOrder: []string{"cosigner_public_key"},
		},
		cosigner: cosignerState{loaded: true},
	}

	next, _ := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("deadbeef")})
	m = next.(Model)
	if got := m.forms.genericLSigParams["cosigner_public_key"]; got != "" {
		t.Fatalf("raw key input = %q, want blocked", got)
	}
	next, _ = m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.viewState != ViewCosignerImportForm {
		t.Fatalf("viewState = %v, want in-flow cosigner enrollment", m.viewState)
	}
}

func TestCosignerImportResultRefreshesMetadataAndSelectsImportedWitness(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                  "guarded.v1",
		CosignerComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "cosigner_public_key", Type: "bytes", Required: true, MaxLength: 64,
		}},
	}})
	m := Model{
		viewState: ViewCosignerImporting,
		forms: formsState{
			generateKeyType:       0,
			genericLSigParams:     map[string]string{"cosigner_public_key": ""},
			genericLSigParamOrder: []string{"cosigner_public_key"},
		},
		cosigner: cosignerState{envelopeJSON: "public-only"},
	}

	next, _ := m.Update(CosignerImportResultMsg{
		Success: true,
		Reference: CosignerReferenceInfo{
			Name: "lab", ComponentKey: testWitnessID1, KeyType: "witness.v1",
		},
	})
	m = next.(Model)
	if m.cosigner.envelopeJSON != "" {
		t.Fatal("public envelope remained in transient state after import")
	}
	next, _ = m.Update(KeyTypesMsg{KeyTypes: []protocol.KeyTypeInfo{{
		KeyType:                  "guarded.v1",
		CosignerComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "cosigner_public_key", Type: "bytes", Required: true, MaxLength: 64,
		}},
	}}})
	m = next.(Model)
	if m.cosigner.pendingWitnessID != testWitnessID1 {
		t.Fatal("stale key-type inventory cleared the pending imported witness")
	}

	next, _ = m.Update(KeyTypesMsg{KeyTypes: []protocol.KeyTypeInfo{{
		KeyType:                  "guarded.v1",
		CosignerComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "cosigner", Type: "select", Required: true,
			Options: []string{testWitnessID1}, Default: testWitnessID1,
		}},
	}}})
	m = next.(Model)
	if got := m.forms.genericLSigParams["cosigner"]; got != testWitnessID1 {
		t.Fatalf("resumed cosigner selection = %q, want imported Witness Key ID", got)
	}
	if _, ok := m.forms.genericLSigParams["cosigner_public_key"]; ok {
		t.Fatal("resumed form retained raw cosigner_public_key input")
	}
}

func TestPrepareCosignerImportReviewVerifiesEnvelopeAndShowsFullID(t *testing.T) {
	publicKey := make([]byte, witness.Falcon1024PublicKeySize)
	for index := range publicKey {
		publicKey[index] = byte(index)
	}
	keyID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := witness.NewPublicReference(witness.Falcon1024V1, keyID, hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(reference)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cosigner.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	m := Model{
		width:  48,
		height: 30,
		cosigner: cosignerState{
			importPath:      path,
			importName:      "lab",
			requiredKeyType: witness.Falcon1024V1,
		},
	}
	m = m.prepareCosignerImportReview()
	if m.viewState != ViewCosignerImportReview || m.cosigner.previewWitnessID != keyID {
		t.Fatalf("review state = %v/%q error=%q", m.viewState, m.cosigner.previewWitnessID, m.cosigner.importError)
	}
	rendered := stripANSI(m.renderCosignerImportReview())
	for _, group := range strings.Fields(groupedWitnessKeyID(keyID)) {
		if !strings.Contains(rendered, group) {
			t.Fatalf("review omitted Witness Key ID group %q:\n%s", group, rendered)
		}
	}
	if strings.Contains(rendered, reference.PublicKeyHex) {
		t.Fatal("review rendered full public-key hex")
	}
}

// The key file is the public key and nothing else; one that carries an
// endpoint block is not a key file and is refused before review.
func TestPrepareCosignerImportReviewRejectsFileWithEndpoint(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	data, err := witness.MarshalPublicReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	withEndpoint := strings.Replace(string(data), "{\n", "{\n  \"endpoint\": {\"url\": \"ssh://cosigner.example:2223\"},\n", 1)
	path := filepath.Join(t.TempDir(), "lab.aplane-cosigner.json")
	if err := os.WriteFile(path, []byte(withEndpoint), 0o600); err != nil {
		t.Fatal(err)
	}
	m := Model{
		width: 100, height: 40, dataDir: t.TempDir(),
		cosigner: cosignerState{importPath: path, importName: "lab"},
	}
	m = m.prepareCosignerImportReview()
	if m.viewState == ViewCosignerImportReview || !strings.Contains(m.cosigner.importError, "invalid cosigner key file") {
		t.Fatalf("review state = %v error=%q, want a refusal", m.viewState, m.cosigner.importError)
	}
}

func TestPrepareCosignerImportReviewDefaultsNameFromWitnessID(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	data, err := witness.MarshalPublicReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "---.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	m := Model{cosigner: cosignerState{importPath: path}}
	m = m.prepareCosignerImportReview()
	if m.viewState != ViewCosignerImportReview {
		t.Fatalf("view state = %v, error = %q", m.viewState, m.cosigner.importError)
	}
	if want := suggestedCosignerReferenceName(reference.WitnessKeyID); m.cosigner.importName != want {
		t.Fatalf("default import name = %q, want %q", m.cosigner.importName, want)
	}
}

func testTUIEnrollmentReference(t *testing.T) witness.PublicReference {
	t.Helper()
	publicKey := bytes.Repeat([]byte{0x36}, witness.Falcon1024PublicKeySize)
	keyID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := witness.NewPublicReference(witness.Falcon1024V1, keyID, hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func newGuardedGenerationModel(references ...CosignerReferenceInfo) Model {
	return Model{
		width:     100,
		height:    40,
		viewState: ViewGenerateParams,
		forms: formsState{
			generateKeyType:       0,
			generateFocus:         0,
			genericLSigParams:     map[string]string{"cosigner": "", "note": "kept"},
			genericLSigParamOrder: []string{"cosigner", "note"},
		},
		cosigner: cosignerState{loaded: true, references: references},
	}
}

func setGuardedGenerationKeyType(t *testing.T) {
	t.Helper()
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                  "guarded.v1",
		DisplayName:              "Guarded",
		CosignerComponentKeyType: witness.Falcon1024V1,
		CreationParams: []protocol.TemplateParamInfo{
			{Name: "cosigner", Type: "select", Required: true},
			{Name: "note", Type: "string"},
		},
	}})
	t.Cleanup(func() { setServerKeyTypes(nil) })
}

func writeTUISetupFile(t *testing.T, reference witness.PublicReference) string {
	t.Helper()
	data, err := witness.MarshalPublicReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lab.aplane-cosigner.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The account-creation picker offers the setup file every time, not only when
// no reference exists yet, so the Cosigners manager is never a required step.
func TestCosignerPickerOffersSetupFileAndPasteAlongsideReferences(t *testing.T) {
	setGuardedGenerationKeyType(t)
	m := newGuardedGenerationModel(CosignerReferenceInfo{Name: "treasury", ComponentKey: testWitnessID1, KeyType: witness.Falcon1024V1})

	next, _ := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.viewState != ViewCosignerPicker || len(m.cosigner.choices) != 1 {
		t.Fatalf("viewState = %v choices = %#v, want the picker with one reference", m.viewState, m.cosigner.choices)
	}
	rendered := stripANSI(m.renderCosignerPicker())
	for _, want := range []string{"treasury", "Use setup file...", "Paste public JSON..."} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("picker omitted %q:\n%s", want, rendered)
		}
	}

	file, _ := m.handleCosignerPickerKeys(tea.KeyMsg{Type: tea.KeyDown})
	file, _ = file.(Model).handleCosignerPickerKeys(tea.KeyMsg{Type: tea.KeyEnter})
	fileModel := file.(Model)
	if fileModel.viewState != ViewCosignerImportForm || fileModel.cosigner.importPaste ||
		fileModel.cosigner.paramName != "cosigner" || fileModel.cosigner.requiredKeyType != witness.Falcon1024V1 ||
		fileModel.cosigner.returnView != ViewGenerateParams {
		t.Fatalf("file import state = %#v, want the in-flow file form bound to the account's cosigner field", fileModel.cosigner)
	}

	paste := tea.Model(m)
	for range 3 { // The selection stops at the last row.
		paste, _ = paste.(Model).handleCosignerPickerKeys(tea.KeyMsg{Type: tea.KeyDown})
	}
	paste, _ = paste.(Model).handleCosignerPickerKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if pasteModel := paste.(Model); pasteModel.viewState != ViewCosignerImportForm || !pasteModel.cosigner.importPaste {
		t.Fatalf("paste import state = %#v, want the in-flow paste form", pasteModel.cosigner)
	}
}

// A setup file whose key is already imported is reused under its existing
// name. Nothing is sent to the signer and the other parameters are kept.
func TestAccountCreationReusesAlreadyImportedSetupFileKey(t *testing.T) {
	setGuardedGenerationKeyType(t)
	reference := testTUIEnrollmentReference(t)
	m := newGuardedGenerationModel(
		CosignerReferenceInfo{Name: "zeta", ComponentKey: reference.WitnessKeyID, KeyType: reference.KeyType},
		CosignerReferenceInfo{Name: "treasury", ComponentKey: reference.WitnessKeyID, KeyType: reference.KeyType},
		CosignerReferenceInfo{Name: "unrelated", ComponentKey: testWitnessID1, KeyType: reference.KeyType},
	)
	next, _ := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model).beginGenerationCosignerImport(false)
	m.cosigner.importPath = writeTUISetupFile(t, reference)

	m = m.prepareCosignerImportReview()
	if m.viewState != ViewCosignerImportReview || strings.Join(m.cosigner.reuseAliases, ",") != "treasury,zeta" {
		t.Fatalf("viewState = %v reuse = %v error = %q, want the existing names offered", m.viewState, m.cosigner.reuseAliases, m.cosigner.importError)
	}
	rendered := stripANSI(m.renderCosignerImportReview())
	for _, want := range []string{"This key is already imported as treasury.", "USE TREASURY", "Nothing is imported or renamed."} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("reuse review omitted %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "IMPORT\n") {
		t.Fatalf("reuse review offered an import:\n%s", rendered)
	}

	next, cmd := m.handleCosignerImportReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if cmd != nil {
		t.Fatalf("reuse issued a command %v, want no import request", cmd)
	}
	if m.viewState != ViewGenerateParams || m.forms.genericLSigParams["cosigner"] != reference.WitnessKeyID {
		t.Fatalf("viewState = %v params = %#v, want the generation form with the cosigner filled", m.viewState, m.forms.genericLSigParams)
	}
	if m.forms.genericLSigParams["note"] != "kept" {
		t.Fatalf("params = %#v, want the other parameters preserved", m.forms.genericLSigParams)
	}
	if m.cosigner.paramName != "" || m.cosigner.envelopeJSON != "" || len(m.cosigner.reuseAliases) != 0 {
		t.Fatalf("cosigner state = %#v, want the import state cleared", m.cosigner)
	}
}

// A new key from a setup file is still reviewed and imported; choosing the file
// never generates the account by itself.
func TestAccountCreationImportsNewSetupFileKeyWithReview(t *testing.T) {
	setGuardedGenerationKeyType(t)
	reference := testTUIEnrollmentReference(t)
	m := newGuardedGenerationModel(CosignerReferenceInfo{Name: "unrelated", ComponentKey: testWitnessID1, KeyType: reference.KeyType})
	next, _ := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model).beginGenerationCosignerImport(false)
	m.cosigner.importPath = writeTUISetupFile(t, reference)

	m = m.prepareCosignerImportReview()
	if m.viewState != ViewCosignerImportReview || len(m.cosigner.reuseAliases) != 0 || m.cosigner.envelopeJSON == "" {
		t.Fatalf("viewState = %v reuse = %v error = %q, want an import review", m.viewState, m.cosigner.reuseAliases, m.cosigner.importError)
	}
	rendered := stripANSI(m.renderCosignerImportReview())
	for _, want := range []string{"Compare the complete Witness Key ID before importing.", "The imported key stays in Cosigners"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("import review omitted %q:\n%s", want, rendered)
		}
	}
	if m.forms.genericLSigParams["cosigner"] != "" {
		t.Fatalf("params = %#v, want no cosigner chosen before the import is confirmed", m.forms.genericLSigParams)
	}
}

// The Cosigners manager keeps importing explicitly; reuse applies only when a
// file is chosen while creating an account.
func TestManagerImportDoesNotOfferReuse(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	m := Model{width: 100, height: 40, cosigner: cosignerState{loaded: true, references: []CosignerReferenceInfo{
		{Name: "treasury", ComponentKey: reference.WitnessKeyID, KeyType: reference.KeyType},
	}}}
	m = m.beginManagerCosignerImport()
	m.cosigner.importPath = writeTUISetupFile(t, reference)
	m = m.prepareCosignerImportReview()
	if m.viewState != ViewCosignerImportReview || len(m.cosigner.reuseAliases) != 0 {
		t.Fatalf("viewState = %v reuse = %v, want the ordinary import review", m.viewState, m.cosigner.reuseAliases)
	}
}

func TestCosignerExportResultPointsAtSetupFlow(t *testing.T) {
	m := Model{width: 100, height: 40, cosigner: cosignerState{
		exportWitnessID: testWitnessID1, exportWrittenPath: "/tmp/lab.aplane-cosigner.json",
	}}
	rendered := stripANSI(m.renderCosignerExportResult())
	for _, want := range []string{
		"Cosigner Key Exported",
		"Generate account -> Cosigner -> Use key file.",
		"endpoints add ssh://",
		"later keys on it need no client change",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("export result omitted %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "cosigner add") {
		t.Fatalf("export result still names the former command:\n%s", rendered)
	}
}
