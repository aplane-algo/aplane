// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cosigner/enrollment"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	tea "github.com/charmbracelet/bubbletea"
)

func TestCosignerPasteUsesImportReview(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	bundleJSON, err := enrollment.Marshal(enrollment.Envelope{
		Schema: enrollment.Schema, Witness: reference,
		Endpoint: &endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: "ssh://cosigner.example:2223", SignerPort: 11270},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		data     []byte
		endpoint bool
	}{
		{"witness", witnessJSON, false},
		{"bundle", bundleJSON, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Model{viewState: ViewCosignerReferences, dataDir: t.TempDir()}
			next, _ := m.handleCosignerReferencesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
			m = next.(Model)
			next, cmd := m.handleCosignerImportFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(string(tc.data)), Paste: true})
			m = next.(Model)
			if cmd != nil || m.viewState != ViewCosignerImportForm || m.cosigner.importJSON != string(tc.data) {
				t.Fatal("paste did not capture the complete multiline document without submitting")
			}
			if want := suggestedCosignerReferenceName(reference.WitnessKeyID); m.cosigner.importName != want {
				t.Fatalf("default import name = %q, want %q", m.cosigner.importName, want)
			}
			m.cosigner.importName = "Lab"
			m = m.prepareCosignerImportReview()
			if m.viewState != ViewCosignerImportReview || m.cosigner.previewWitnessID != reference.WitnessKeyID || m.cosigner.importName != "lab" {
				t.Fatalf("unexpected review: %v, %s", m.viewState, m.cosigner.importError)
			}
			if (m.cosigner.previewEndpoint != nil) != tc.endpoint {
				t.Fatal("endpoint review differs from file import")
			}
			if m.cosigner.envelopeJSON != string(witnessJSON) {
				t.Fatal("paste did not produce the canonical import envelope")
			}
			next, _ = m.handleCosignerImportReviewKeys(tea.KeyMsg{Type: tea.KeyEsc})
			m = next.(Model)
			if !m.cosigner.importPaste || m.cosigner.importJSON != string(tc.data) {
				t.Fatal("back from review lost the pasted document")
			}
			m = m.cancelCosignerImport()
			if m.viewState != ViewCosignerReferences || m.cosigner.importJSON != "" || m.cosigner.envelopeJSON != "" || m.cosigner.importPaste {
				t.Fatal("cancel did not clear paste state")
			}
		})
	}
}

func TestCosignerPasteRejectsInvalidAndOversizedInput(t *testing.T) {
	for _, data := range []string{"", "not JSON", `{"schema":"unknown"}`, `{"schema":"aplane.cosigner-enrollment.v1","witness":null}`, strings.Repeat("x", enrollment.MaxEnvelopeBytes+1)} {
		m := Model{}.beginManagerCosignerImport()
		m.cosigner.importPaste = true
		m.cosigner.importName = "lab"
		next, cmd := m.handleCosignerImportFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(data), Paste: true})
		m = next.(Model)
		if cmd != nil || len(m.cosigner.importJSON) > enrollment.MaxEnvelopeBytes {
			t.Fatal("paste exceeded buffer limit or issued a command")
		}
		m = m.prepareCosignerImportReview()
		if m.viewState != ViewCosignerImportForm || m.cosigner.importError == "" || m.cosigner.envelopeJSON != "" {
			t.Fatal("invalid document reached review")
		}
	}
}

func TestCosignerPasteRoutesBracketedPasteToNameField(t *testing.T) {
	m := Model{}.beginManagerCosignerImport()
	m.cosigner.importPaste = true
	m.cosigner.importFocus = 1
	m.cosigner.importName = "ops-"
	m.cosigner.importError = "old error"

	next, cmd := m.handleCosignerImportFormKeys(tea.KeyMsg{
		Type: tea.KeyRunes, Runes: []rune("cosigner-1"), Paste: true,
	})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	m = next.(Model)
	if m.cosigner.importName != "ops-cosigner-1" {
		t.Fatalf("importName = %q, want pasted name", m.cosigner.importName)
	}
	if m.cosigner.importError != "" {
		t.Fatalf("importError = %q, want cleared", m.cosigner.importError)
	}
}

func TestCosignerImportDefaultFollowsSourceUnlessEdited(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	data, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	m := Model{cosigner: cosignerState{importName: "cosigner-old", importNameDefault: "cosigner-old", importPaste: true}}
	next, _ := m.handleCosignerImportFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(string(data)), Paste: true})
	m = next.(Model)
	if m.cosigner.importName == "cosigner-old" || m.cosigner.importName == "" {
		t.Fatal("replacement paste retained stale default")
	}
	m.cosigner.importName = "my-cosigner"
	next, _ = m.handleCosignerImportFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(string(data)), Paste: true})
	if next.(Model).cosigner.importName != "my-cosigner" {
		t.Fatal("replacement paste overwrote custom name")
	}
	m = Model{cosigner: cosignerState{importName: "old", importNameDefault: "old", importPath: "/tmp/New.aplane-cosigner.json"}}
	m = m.suggestCosignerImportNameFromPath()
	if m.cosigner.importName != "new" {
		t.Fatal("replacement path retained stale default")
	}
	m.cosigner.importName = "custom"
	m.cosigner.importPath = "/tmp/another.json"
	m = m.suggestCosignerImportNameFromPath()
	if m.cosigner.importName != "custom" {
		t.Fatal("replacement path overwrote custom name")
	}
}
