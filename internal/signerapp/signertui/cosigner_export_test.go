// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cosigner/enrollment"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

func TestCosignerJSONTerminalDisplayPreservesEntireDocument(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	document, err := enrollment.MarshalWitness(reference)
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
	witnessJSON, err := enrollment.MarshalWitness(reference)
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
			exportHost:       "cosigner.example",
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

func TestCosignerExportOffersConfiguredAdvertisedEndpoint(t *testing.T) {
	m := Model{
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole: "cosigner", EndpointAdvertiseURL: "ssh://cosigner.example:2223", SignerPort: 11270,
		}},
	}
	nextModel, _ := m.openCosignerExportFor(testWitnessID1, witness.Falcon1024V1, ViewKeyDetails)
	next := nextModel.(Model)
	if next.cosigner.exportEndpoint == nil || next.cosignerExportHasHostField() || next.cosignerExportButtonFocus() != 1 {
		t.Fatalf("endpoint export state = endpoint=%#v button=%d", next.cosigner.exportEndpoint, next.cosignerExportButtonFocus())
	}
	if next.cosigner.exportEndpoint.URL != "ssh://cosigner.example:2223" || next.cosigner.exportEndpoint.SignerPort != 11270 {
		t.Fatalf("endpoint = %#v", next.cosigner.exportEndpoint)
	}
	view := stripANSI(next.renderCosignerExportPath())
	if !strings.Contains(view, "ssh://cosigner.example:2223") || !strings.Contains(view, "no token or host trust") ||
		strings.Contains(view, "Client-reachable host") {
		t.Fatalf("export review missing endpoint boundary:\n%s", view)
	}
}

func TestCosignerExportRequiresHostWithoutAdvertisedEndpoint(t *testing.T) {
	m := Model{
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole: "cosigner", SSHListenAddress: "0.0.0.0", SSHPort: 2223, SignerPort: 11271,
		}},
	}
	nextModel, _ := m.openCosignerExportFor(testWitnessID1, witness.Falcon1024V1, ViewKeyDetails)
	next := nextModel.(Model)
	if !next.cosignerExportHasHostField() || next.cosignerExportButtonFocus() != 2 {
		t.Fatalf("host field missing: button=%d", next.cosignerExportButtonFocus())
	}
	if !strings.Contains(stripANSI(next.renderCosignerExportPath()), "Client-reachable host") {
		t.Fatal("export view does not ask for the client-reachable host")
	}

	next.cosigner.exportFocus = next.cosignerExportButtonFocus()
	nextModel, cmd := next.handleCosignerExportPathKeys(tea.KeyMsg{Type: tea.KeyEnter})
	blocked := nextModel.(Model)
	if cmd != nil || blocked.viewState != ViewCosignerExportPath || !strings.Contains(blocked.cosigner.exportError, "host is required") {
		t.Fatalf("empty host export = view %v error %q cmd %v", blocked.viewState, blocked.cosigner.exportError, cmd)
	}

	next.cosigner.exportFocus = 1
	for _, r := range "cosigner.example" {
		nextModel, _ = next.handleCosignerExportPathKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		next = nextModel.(Model)
	}
	if next.cosigner.exportPath == "" || strings.Contains(next.cosigner.exportPath, "cosigner.example") {
		t.Fatalf("host typing leaked into output path: %q", next.cosigner.exportPath)
	}
	endpoint, err := next.cosignerExportEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.URL != "ssh://cosigner.example:2223" || endpoint.SignerPort != 11271 {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	next.cosigner.exportFocus = next.cosignerExportButtonFocus()
	nextModel, cmd = next.handleCosignerExportPathKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if started := nextModel.(Model); cmd == nil || started.viewState != ViewCosignerExporting {
		t.Fatalf("export with host did not start: view %v", started.viewState)
	}
}

func TestCosignerExportRejectsHostWithPort(t *testing.T) {
	m := Model{cosigner: cosignerState{exportHost: "cosigner.example:2223"}}
	if _, err := m.cosignerExportEndpoint(); err == nil || !strings.Contains(err.Error(), "invalid host") {
		t.Fatalf("err = %v, want invalid host", err)
	}
}

func TestCosignerExportWarnsWhenSSHListensOnLoopback(t *testing.T) {
	remote := &endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: "ssh://cosigner.example:2223"}
	local := &endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: "ssh://127.0.0.1:2223"}
	for _, test := range []struct {
		name     string
		listen   string
		endpoint *endpointrefs.Envelope
		warn     bool
	}{
		{"default loopback remote", "", remote, true},
		{"loopback remote", "127.0.0.1", remote, true},
		{"loopback local", "127.0.0.1", local, false},
		{"all interfaces remote", "0.0.0.0", remote, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := Model{admin: adminPanelState{settings: &AdminSettings{SSHListenAddress: test.listen}}}
			if got := m.cosignerExportListenWarning(test.endpoint) != ""; got != test.warn {
				t.Fatalf("warning = %t, want %t", got, test.warn)
			}
		})
	}
}

func TestComposeCosignerExportArtifactAlwaysBuildsCombinedBundle(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://cosigner.example:2223", SignerPort: 11270,
	}

	combined, err := composeCosignerExportArtifact(string(witnessJSON), endpoint)
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
