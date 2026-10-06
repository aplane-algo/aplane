// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

func TestCosignerJSONTerminalDisplayPreservesEntireDocument(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	document, err := witness.MarshalPublicReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	display := &cosignerJSONTerminalDisplay{document: string(document)}
	display.SetStdin(strings.NewReader("\n"))
	display.SetStdout(&output)
	if err := display.Run(); err != nil {
		t.Fatal(err)
	}
	prefix := "\nCosigner key JSON — select the document below to copy:\n\n"
	suffix := "\n\nPress Enter to return to the export screen.\n"
	copied := strings.TrimSuffix(strings.TrimPrefix(output.String(), prefix), suffix)
	if copied != string(document) {
		t.Fatal("terminal output changed the JSON bytes")
	}
	if _, err := witness.ParsePublicReference([]byte(copied)); err != nil {
		t.Fatalf("copied JSON cannot be imported: %v", err)
	}

}

func TestCosignerKeyDetailsOpensLocalEnrollmentExport(t *testing.T) {
	m := Model{
		viewState: ViewKeyDetails,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}},
		details:   keyDetailsState{address: testWitnessID1, keyType: witness.Falcon1024V1},
	}
	nextModel, cmd := m.handleKeyDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil before path confirmation", cmd)
	}
	if next.viewState != ViewCosignerExportPath {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewCosignerExportPath)
	}
	if next.cosigner.exportWitnessID != testWitnessID1 || !strings.HasSuffix(next.cosigner.exportPath, ".json") {
		t.Fatalf("export state = ID %q path %q", next.cosigner.exportWitnessID, next.cosigner.exportPath)
	}
	if !strings.Contains(next.viewFooterText(), "Enter: Select") {
		t.Fatalf("export footer = %q", next.viewFooterText())
	}
}

func TestCosignerEnrollmentExportShowsJSONWithoutPath(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	witnessJSON, err := witness.MarshalPublicReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	m := Model{
		viewState: ViewCosignerExportPath,
		width:     100,
		height:    30,
		cosigner: cosignerState{
			exportWitnessID:  reference.WitnessKeyID,
			exportReturnView: ViewKeyDetails,
		},
	}
	m.cosigner.exportFocus = m.cosignerExportJSONButtonFocus()
	nextModel, cmd := m.handleCosignerExportPathKeys(tea.KeyMsg{Type: tea.KeyEnter})
	next := nextModel.(Model)
	if cmd == nil || next.viewState != ViewCosignerExporting || !next.cosigner.exportShowJSON {
		t.Fatalf("show JSON start = view %v show=%t cmd=%v", next.viewState, next.cosigner.exportShowJSON, cmd)
	}
	if next.cosigner.exportPath != "" {
		t.Fatalf("show JSON unexpectedly required an output path: %q", next.cosigner.exportPath)
	}

	nextModel, cmd = next.Update(CosignerExportResultMsg{
		Success: true, WitnessKeyID: reference.WitnessKeyID, EnvelopeJSON: string(witnessJSON),
	})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerExportJSON || cmd == nil {
		t.Fatalf("show JSON did not immediately start terminal display: view %v cmd %v", next.viewState, cmd)
	}
	nextModel, _ = next.Update(cosignerJSONTerminalClosedMsg{})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerExportPath || next.cosigner.exportShowJSON {
		t.Fatal("closing terminal output did not return to the export screen")
	}

}

func TestCosignerExportEditsOutputPathDirectly(t *testing.T) {
	m := Model{cosigner: cosignerState{exportPath: "custom.aplane-cosigner.json"}}
	nextModel, _ := m.handleCosignerExportPathKeys(tea.KeyMsg{Type: tea.KeyBackspace})
	next := nextModel.(Model)
	if next.cosigner.exportPath != "custom.aplane-cosigner.jso" {
		t.Fatalf("export path = %q", next.cosigner.exportPath)
	}
	view := stripANSI(next.renderCosignerExportPath())
	if strings.Contains(view, "Suggested name") || !strings.Contains(view, "Output path") {
		t.Fatalf("unexpected export fields:\n%s", view)
	}
}

// The export is the public key and nothing else. The cosigner's address is
// shown as what to type on a client, never written into the file.
func TestCosignerExportCarriesNoEndpoint(t *testing.T) {
	m := Model{
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole: "cosigner", EndpointAdvertiseURL: "ssh://cosigner.example:2223", SignerPort: 11270,
		}},
	}
	nextModel, _ := m.openCosignerExportFor(testWitnessID1, witness.Falcon1024V1, ViewKeyDetails)
	next := nextModel.(Model)
	if next.cosignerExportButtonFocus() != 1 || next.cosignerExportJSONButtonFocus() != 2 {
		t.Fatalf("export focus layout = %d/%d, want path, export, show JSON", next.cosignerExportButtonFocus(), next.cosignerExportJSONButtonFocus())
	}
	view := stripANSI(next.renderCosignerExportPath())
	if strings.Contains(view, "cosigner.example") || strings.Contains(view, "Client-reachable host") || !strings.Contains(view, "Public key only") {
		t.Fatalf("export screen mentions an endpoint:\n%s", view)
	}

	// The export starts without asking for a host.
	next.cosigner.exportFocus = next.cosignerExportButtonFocus()
	nextModel, cmd := next.handleCosignerExportPathKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if started := nextModel.(Model); cmd == nil || started.viewState != ViewCosignerExporting {
		t.Fatalf("export did not start: view %v", started.viewState)
	}

	// The result names the advertised address for endpoints add.
	next.cosigner.exportWrittenPath = "/tmp/lab.aplane-cosigner.json"
	result := stripANSI(next.renderCosignerExportResult())
	if !strings.Contains(result, "endpoints add ssh://cosigner.example:2223") || strings.Contains(result, "endpoints add /tmp") {
		t.Fatalf("export result does not point clients at the cosigner's address:\n%s", result)
	}
	unconfigured := Model{admin: adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}}, cosigner: next.cosigner}
	if result := stripANSI(unconfigured.renderCosignerExportResult()); !strings.Contains(result, "endpoints add ssh://<this cosigner's host>") {
		t.Fatalf("export result without advertise_url lacks the placeholder:\n%s", result)
	}
}

func TestComposeCosignerExportArtifactIsTheKeyOnly(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	witnessJSON, err := witness.MarshalPublicReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := composeCosignerExportArtifact(string(witnessJSON))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := witness.ParsePublicReference([]byte(artifact))
	if err != nil {
		t.Fatalf("exported file is not a public witness reference: %v", err)
	}
	if parsed != reference || strings.Contains(artifact, "endpoint") {
		t.Fatalf("artifact = %s", artifact)
	}
	if _, err := composeCosignerExportArtifact(`{"schema":"aplane.witness-key-public.v1"}`); err == nil {
		t.Fatal("an invalid daemon document was exported")
	}
}

func TestGeneratedCosignerKeyCanExportWithoutReopeningDetails(t *testing.T) {
	m := Model{
		viewState: ViewGenerateDisplay,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}},
		forms: formsState{
			generatedAddress: testWitnessID1,
			generatedKeyType: witness.Falcon1024V1,
		},
	}
	nextModel, _ := m.handleGenerateDisplayKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if next.viewState != ViewCosignerExportPath || next.cosigner.exportReturnView != ViewGenerateDisplay {
		t.Fatalf("generated export = view %v return %v", next.viewState, next.cosigner.exportReturnView)
	}

	nextModel, _ = next.handleCosignerExportPathKeys(tea.KeyMsg{Type: tea.KeyEsc})
	next = nextModel.(Model)
	if next.viewState != ViewGenerateDisplay {
		t.Fatalf("export cancel view = %v, want %v", next.viewState, ViewGenerateDisplay)
	}
}

func TestCosignerEnrollmentExportWritesOperatorPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab-cosigner.json")
	const envelope = `{"schema":"aplane.witness-key-public.v1"}`
	msg := writeCosignerPublicEnvelopeCmd(path, envelope)()
	written, ok := msg.(CosignerExportWrittenMsg)
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

	m := Model{viewState: ViewCosignerExporting, cosigner: cosignerState{exportWitnessID: testWitnessID1}}
	nextModel, _ := m.Update(written)
	next := nextModel.(Model)
	if next.viewState != ViewCosignerExportResult || next.cosigner.exportWrittenPath != path {
		t.Fatalf("write result = view %v path %q", next.viewState, next.cosigner.exportWrittenPath)
	}
}

func TestCosignerEnrollmentExportRejectsInconsistentResponse(t *testing.T) {
	m := Model{
		viewState: ViewCosignerExporting,
		cosigner: cosignerState{
			exportWitnessID: testWitnessID1,
			exportPath:      "unused.json",
		},
	}
	nextModel, _ := m.Update(CosignerExportResultMsg{
		Success:      true,
		WitnessKeyID: testWitnessID2,
		EnvelopeJSON: `{}`,
	})
	next := nextModel.(Model)
	if next.viewState != ViewCosignerExportPath || !strings.Contains(next.cosigner.exportError, "inconsistent") {
		t.Fatalf("response result = view %v error %q", next.viewState, next.cosigner.exportError)
	}
}
