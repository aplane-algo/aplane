// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

func TestSentryJSONTerminalDisplayPreservesEntireDocument(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	document, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	display := &sentryJSONTerminalDisplay{document: string(document)}
	display.SetStdin(strings.NewReader("\n"))
	display.SetStdout(&output)
	if err := display.Run(); err != nil {
		t.Fatal(err)
	}
	prefix := "\nSentry key JSON — select the document below to copy:\n\n"
	suffix := "\n\nPress Enter to return to the export screen.\n"
	copied := strings.TrimSuffix(strings.TrimPrefix(output.String(), prefix), suffix)
	if copied != string(document) {
		t.Fatal("terminal output changed the JSON bytes")
	}
	if _, err := witness.ParsePublicReference([]byte(copied)); err != nil {
		t.Fatalf("copied JSON cannot be imported: %v", err)
	}

}

func TestSentryKeyDetailsOpensLocalEnrollmentExport(t *testing.T) {
	m := Model{
		viewState: ViewKeyDetails,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "sentry"}},
		details:   keyDetailsState{address: testWitnessID1, keyType: witness.Falcon1024V1},
	}
	nextModel, cmd := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil before path confirmation", cmd)
	}
	if next.viewState != ViewSentryExportPath {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewSentryExportPath)
	}
	if next.sentry.exportWitnessID != testWitnessID1 || !strings.HasSuffix(next.sentry.exportPath, ".json") {
		t.Fatalf("export state = ID %q path %q", next.sentry.exportWitnessID, next.sentry.exportPath)
	}
	if !strings.Contains(next.viewFooterText(), "Enter: Select") {
		t.Fatalf("export footer = %q", next.viewFooterText())
	}
}

func TestSentryEnrollmentExportShowsJSONWithoutPath(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	m := Model{
		viewState: ViewSentryExportPath,
		width:     100,
		height:    30,
		sentry: sentryState{
			exportWitnessID:  reference.WitnessKeyID,
			exportReturnView: ViewKeyDetails,
		},
	}
	m.sentry.exportFocus = m.sentryExportJSONButtonFocus()
	nextModel, cmd := m.handleSentryExportPathKeys(tea.KeyMsg{Type: tea.KeyEnter})
	next := nextModel.(Model)
	if cmd == nil || next.viewState != ViewSentryExporting || !next.sentry.exportShowJSON {
		t.Fatalf("show JSON start = view %v show=%t cmd=%v", next.viewState, next.sentry.exportShowJSON, cmd)
	}
	if next.sentry.exportPath != "" {
		t.Fatalf("show JSON unexpectedly required an output path: %q", next.sentry.exportPath)
	}

	nextModel, cmd = next.Update(SentryExportResultMsg{
		Success: true, WitnessKeyID: reference.WitnessKeyID, EnvelopeJSON: string(witnessJSON),
	})
	next = nextModel.(Model)
	if next.viewState != ViewSentryExportJSON || cmd == nil {
		t.Fatalf("show JSON did not immediately start terminal display: view %v cmd %v", next.viewState, cmd)
	}
	nextModel, _ = next.Update(sentryJSONTerminalClosedMsg{})
	next = nextModel.(Model)
	if next.viewState != ViewSentryExportPath || next.sentry.exportShowJSON {
		t.Fatal("closing terminal output did not return to the export screen")
	}

}

func TestSentryExportEditsOutputPathDirectly(t *testing.T) {
	m := Model{sentry: sentryState{exportPath: "custom.aplane-sentry.json"}}
	nextModel, _ := m.handleSentryExportPathKeys(tea.KeyMsg{Type: tea.KeyBackspace})
	next := nextModel.(Model)
	if next.sentry.exportPath != "custom.aplane-sentry.jso" {
		t.Fatalf("export path = %q", next.sentry.exportPath)
	}
	view := stripANSI(next.renderSentryExportPath())
	if strings.Contains(view, "Suggested name") || !strings.Contains(view, "Output path") {
		t.Fatalf("unexpected export fields:\n%s", view)
	}
}

func TestSentryExportOffersConfiguredAdvertisedEndpoint(t *testing.T) {
	m := Model{
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole: "sentry", EndpointAdvertiseURL: "ssh://sentry.example:2223", SignerPort: 11270,
		}},
	}
	nextModel, _ := m.openSentryExportFor(testWitnessID1, witness.Falcon1024V1, ViewKeyDetails)
	next := nextModel.(Model)
	if next.sentry.exportEndpoint == nil || !next.sentry.exportIncludeEndpoint || next.sentryExportButtonFocus() != 2 {
		t.Fatalf("endpoint export state = endpoint=%#v include=%t button=%d", next.sentry.exportEndpoint, next.sentry.exportIncludeEndpoint, next.sentryExportButtonFocus())
	}
	if next.sentry.exportEndpoint.URL != "ssh://sentry.example:2223" || next.sentry.exportEndpoint.SignerPort != 11270 {
		t.Fatalf("endpoint = %#v", next.sentry.exportEndpoint)
	}
	view := stripANSI(next.renderSentryExportPath())
	if !strings.Contains(view, "[x] Include advertised endpoint") || !strings.Contains(view, "no token or host trust") {
		t.Fatalf("export review missing endpoint boundary:\n%s", view)
	}
}

func TestComposeSentryExportArtifactBuildsCombinedBundleOnlyWhenSelected(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://sentry.example:2223", SignerPort: 11270,
	}

	combined, err := composeSentryExportArtifact(string(witnessJSON), endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := enrollment.ParseArtifact([]byte(combined))
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Endpoint == nil || artifact.Endpoint.URL != endpoint.URL || artifact.Witness.WitnessKeyID != reference.WitnessKeyID {
		t.Fatalf("artifact = %+v", artifact)
	}

	witnessOnly, err := composeSentryExportArtifact(string(witnessJSON), endpoint, false)
	if err != nil {
		t.Fatal(err)
	}
	if witnessOnly != string(witnessJSON) {
		t.Fatal("endpoint opt-out changed the canonical witness envelope")
	}
}

func TestGeneratedSentryKeyCanExportWithoutReopeningDetails(t *testing.T) {
	m := Model{
		viewState: ViewGenerateDisplay,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "sentry"}},
		forms: formsState{
			generatedAddress: testWitnessID1,
			generatedKeyType: witness.Falcon1024V1,
		},
	}
	nextModel, _ := m.handleGenerateDisplayKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if next.viewState != ViewSentryExportPath || next.sentry.exportReturnView != ViewGenerateDisplay {
		t.Fatalf("generated export = view %v return %v", next.viewState, next.sentry.exportReturnView)
	}

	nextModel, _ = next.handleSentryExportPathKeys(tea.KeyMsg{Type: tea.KeyEsc})
	next = nextModel.(Model)
	if next.viewState != ViewGenerateDisplay {
		t.Fatalf("export cancel view = %v, want %v", next.viewState, ViewGenerateDisplay)
	}
}

func TestSentryEnrollmentExportWritesOperatorPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab-sentry.json")
	const envelope = `{"schema":"aplane.witness-key-public.v1"}`
	msg := writeSentryPublicEnvelopeCmd(path, envelope)()
	written, ok := msg.(SentryExportWrittenMsg)
	if !ok {
		t.Fatalf("message type = %T", msg)
	}
	if written.Error != nil {
		t.Fatalf("write error = %v", written.Error)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != envelope {
		t.Fatalf("written envelope = %q", data)
	}

	m := Model{viewState: ViewSentryExporting, sentry: sentryState{exportWitnessID: testWitnessID1}}
	nextModel, _ := m.Update(written)
	next := nextModel.(Model)
	if next.viewState != ViewSentryExportResult || next.sentry.exportWrittenPath != path {
		t.Fatalf("write result = view %v path %q", next.viewState, next.sentry.exportWrittenPath)
	}
}

func TestSentryEnrollmentExportRejectsInconsistentResponse(t *testing.T) {
	m := Model{
		viewState: ViewSentryExporting,
		sentry: sentryState{
			exportWitnessID: testWitnessID1,
			exportPath:      "unused.json",
		},
	}
	nextModel, _ := m.Update(SentryExportResultMsg{
		Success:      true,
		WitnessKeyID: testWitnessID2,
		EnvelopeJSON: `{}`,
	})
	next := nextModel.(Model)
	if next.viewState != ViewSentryExportPath || !strings.Contains(next.sentry.exportError, "inconsistent") {
		t.Fatalf("response result = view %v error %q", next.viewState, next.sentry.exportError)
	}
}
