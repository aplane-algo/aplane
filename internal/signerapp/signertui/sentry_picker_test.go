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

	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

const (
	testWitnessID1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testWitnessID2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func TestCompatibleSentryChoicesGroupsAliasesAndFiltersKeyType(t *testing.T) {
	m := Model{sentry: sentryState{references: []SentryReferenceInfo{
		{Name: "z-backup", ComponentKey: testWitnessID1, KeyType: "witness.v1"},
		{Name: "Alpha", ComponentKey: testWitnessID1, KeyType: "witness.v1"},
		{Name: "other", ComponentKey: testWitnessID2, KeyType: "witness.v2"},
	}}}

	choices := m.compatibleSentryChoices("witness.v1")
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

func TestSentryParamHasNoSilentDefaultWithMultipleAuthorities(t *testing.T) {
	param := protocol.TemplateParamInfo{
		Name:    "sentry",
		Type:    "select",
		Options: []string{testWitnessID1, testWitnessID2},
		Default: testWitnessID1,
	}
	def := protocolParamInfosToDefs([]protocol.TemplateParamInfo{param})[0]
	if got := defaultParamValue(def); got != "" {
		t.Fatalf("defaultParamValue() = %q, want no implicit sentry choice", got)
	}

	param.Options = param.Options[:1]
	def = protocolParamInfosToDefs([]protocol.TemplateParamInfo{param})[0]
	if got := defaultParamValue(def); got != testWitnessID1 {
		t.Fatalf("sole defaultParamValue() = %q, want %q", got, testWitnessID1)
	}
}

func TestEmptySentrySelectionUsesFriendlyValidationMessage(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                "guarded.v1",
		DisplayName:            "Guarded",
		SentryComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "sentry", Label: "Sentry", Type: "select", Required: true,
			Options: []string{testWitnessID1, testWitnessID2},
		}},
	}})
	m := Model{
		viewState: ViewGenerateParams,
		forms: formsState{
			generateKeyType:       0,
			generateFocus:         1,
			genericLSigParams:     map[string]string{"sentry": ""},
			genericLSigParamOrder: []string{"sentry"},
		},
		sentry: sentryState{loaded: true},
	}

	next, cmd := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	got := next.(Model)
	if got.viewState != ViewGenerateParams {
		t.Fatalf("viewState = %v, want %v", got.viewState, ViewGenerateParams)
	}
	if got.forms.generateError != "Choose a sentry before continuing" {
		t.Fatalf("generateError = %q", got.forms.generateError)
	}
}

func TestGenerateSentryParamOpensFriendlyPickerAndSubmitsWitnessID(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                "guarded.v1",
		DisplayName:            "Guarded",
		SentryComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "sentry", Type: "select", Required: true,
			Options: []string{testWitnessID1, testWitnessID2}, Default: testWitnessID1,
		}},
	}})
	m := Model{
		viewState: ViewGenerateParams,
		forms: formsState{
			generateKeyType:       0,
			generateFocus:         0,
			genericLSigParams:     map[string]string{"sentry": ""},
			genericLSigParamOrder: []string{"sentry"},
		},
		sentry: sentryState{loaded: true, references: []SentryReferenceInfo{
			{Name: "second", ComponentKey: testWitnessID2, KeyType: "witness.v1"},
			{Name: "first", ComponentKey: testWitnessID1, KeyType: "witness.v1"},
		}},
	}

	next, cmd := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("open picker command = %v, want nil", cmd)
	}
	m = next.(Model)
	if m.viewState != ViewSentryPicker {
		t.Fatalf("viewState = %v, want ViewSentryPicker", m.viewState)
	}
	if m.sentry.choices[0].PrimaryAlias != "first" {
		t.Fatalf("first choice = %#v, want alias-sorted picker", m.sentry.choices[0])
	}

	next, _ = m.handleSentryPickerKeys(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(Model)
	next, _ = m.handleSentryPickerKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if got := m.forms.genericLSigParams["sentry"]; got != testWitnessID2 {
		t.Fatalf("submitted sentry = %q, want canonical Witness Key ID", got)
	}
}

func TestRawSentryPublicKeyInputStartsEnrollmentWhenNoReferenceExists(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                "guarded.v1",
		DisplayName:            "Guarded",
		SentryComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "sentry_public_key", Type: "bytes", Required: true, MaxLength: 64,
		}},
	}})
	m := Model{
		viewState: ViewGenerateParams,
		forms: formsState{
			generateKeyType:       0,
			generateFocus:         0,
			genericLSigParams:     map[string]string{"sentry_public_key": ""},
			genericLSigParamOrder: []string{"sentry_public_key"},
		},
		sentry: sentryState{loaded: true},
	}

	next, _ := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("deadbeef")})
	m = next.(Model)
	if got := m.forms.genericLSigParams["sentry_public_key"]; got != "" {
		t.Fatalf("raw key input = %q, want blocked", got)
	}
	next, _ = m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.viewState != ViewSentryImportForm {
		t.Fatalf("viewState = %v, want in-flow sentry enrollment", m.viewState)
	}
}

func TestSentryImportResultRefreshesMetadataAndSelectsImportedWitness(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:                "guarded.v1",
		SentryComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "sentry_public_key", Type: "bytes", Required: true, MaxLength: 64,
		}},
	}})
	m := Model{
		viewState: ViewSentryImporting,
		forms: formsState{
			generateKeyType:       0,
			genericLSigParams:     map[string]string{"sentry_public_key": ""},
			genericLSigParamOrder: []string{"sentry_public_key"},
		},
		sentry: sentryState{envelopeJSON: "public-only"},
	}

	next, _ := m.Update(SentryImportResultMsg{
		Success: true,
		Reference: SentryReferenceInfo{
			Name: "lab", ComponentKey: testWitnessID1, KeyType: "witness.v1",
		},
	})
	m = next.(Model)
	if m.sentry.envelopeJSON != "" {
		t.Fatal("public envelope remained in transient state after import")
	}
	next, _ = m.Update(KeyTypesMsg{KeyTypes: []protocol.KeyTypeInfo{{
		KeyType:                "guarded.v1",
		SentryComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "sentry_public_key", Type: "bytes", Required: true, MaxLength: 64,
		}},
	}}})
	m = next.(Model)
	if m.sentry.pendingWitnessID != testWitnessID1 {
		t.Fatal("stale key-type inventory cleared the pending imported witness")
	}

	next, _ = m.Update(KeyTypesMsg{KeyTypes: []protocol.KeyTypeInfo{{
		KeyType:                "guarded.v1",
		SentryComponentKeyType: "witness.v1",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "sentry", Type: "select", Required: true,
			Options: []string{testWitnessID1}, Default: testWitnessID1,
		}},
	}}})
	m = next.(Model)
	if got := m.forms.genericLSigParams["sentry"]; got != testWitnessID1 {
		t.Fatalf("resumed sentry selection = %q, want imported Witness Key ID", got)
	}
	if _, ok := m.forms.genericLSigParams["sentry_public_key"]; ok {
		t.Fatal("resumed form retained raw sentry_public_key input")
	}
}

func TestPrepareSentryImportReviewVerifiesEnvelopeAndShowsFullID(t *testing.T) {
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
	path := filepath.Join(t.TempDir(), "sentry.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	m := Model{
		width:  48,
		height: 30,
		sentry: sentryState{
			importPath:      path,
			importName:      "lab",
			requiredKeyType: witness.Falcon1024V1,
		},
	}
	m = m.prepareSentryImportReview()
	if m.viewState != ViewSentryImportReview || m.sentry.previewWitnessID != keyID {
		t.Fatalf("review state = %v/%q error=%q", m.viewState, m.sentry.previewWitnessID, m.sentry.importError)
	}
	rendered := stripANSI(m.renderSentryImportReview())
	for _, group := range strings.Fields(groupedWitnessKeyID(keyID)) {
		if !strings.Contains(rendered, group) {
			t.Fatalf("review omitted Witness Key ID group %q:\n%s", group, rendered)
		}
	}
	if strings.Contains(rendered, reference.PublicKeyHex) {
		t.Fatal("review rendered full public-key hex")
	}
}

func TestPrepareSentryImportReviewSeparatesCombinedBundleEffects(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	endpoint := endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://sentry.example:2223", SignerPort: 11270,
	}
	data, err := enrollment.Marshal(enrollment.Envelope{
		Schema: enrollment.Schema, Witness: reference, Endpoint: &endpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lab.aplane-sentry.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	m := Model{
		width: 100, height: 40, dataDir: t.TempDir(),
		sentry: sentryState{importPath: path, importName: "lab"},
	}
	m = m.prepareSentryImportReview()
	if m.viewState != ViewSentryImportReview || m.sentry.previewEndpoint == nil {
		t.Fatalf("review state = %v endpoint=%#v error=%q", m.viewState, m.sentry.previewEndpoint, m.sentry.importError)
	}
	if _, err := witness.ParsePublicReference([]byte(m.sentry.envelopeJSON)); err != nil {
		t.Fatalf("signer envelope is not the canonical witness-only document: %v", err)
	}
	rendered := stripANSI(m.renderSentryImportReview())
	for _, expected := range []string{
		"Store this public sentry key as lab",
		"Configure the transaction client separately in apshell.",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("review missing %q:\n%s", expected, rendered)
		}
	}
	if strings.Contains(rendered, reference.PublicKeyHex) {
		t.Fatal("combined review rendered full public-key hex")
	}
}

func TestPrepareSentryImportReviewDefaultsNameFromWitnessID(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	data, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "---.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	m := Model{sentry: sentryState{importPath: path}}
	m = m.prepareSentryImportReview()
	if m.viewState != ViewSentryImportReview {
		t.Fatalf("view state = %v, error = %q", m.viewState, m.sentry.importError)
	}
	if want := suggestedSentryReferenceName(reference.WitnessKeyID); m.sentry.importName != want {
		t.Fatalf("default import name = %q, want %q", m.sentry.importName, want)
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
