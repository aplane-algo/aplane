// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	tea "github.com/charmbracelet/bubbletea"
)

func TestSentryPasteUsesImportReview(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	bundleJSON, err := enrollment.Marshal(enrollment.Envelope{
		Schema: enrollment.Schema, Witness: reference,
		Endpoint: &endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: "ssh://sentry.example:2223", SignerPort: 11270},
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
			m := Model{viewState: ViewSentryReferences, dataDir: t.TempDir()}
			next, _ := m.handleSentryReferencesKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
			m = next.(Model)
			next, cmd := m.handleSentryImportFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(string(tc.data)), Paste: true})
			m = next.(Model)
			if cmd != nil || m.viewState != ViewSentryImportForm || m.sentry.importJSON != string(tc.data) {
				t.Fatal("paste did not capture the complete multiline document without submitting")
			}
			if want := suggestedSentryReferenceName(reference.WitnessKeyID); m.sentry.importName != want {
				t.Fatalf("default import name = %q, want %q", m.sentry.importName, want)
			}
			m.sentry.importName = "Lab"
			m = m.prepareSentryImportReview()
			if m.viewState != ViewSentryImportReview || m.sentry.previewWitnessID != reference.WitnessKeyID || m.sentry.importName != "lab" {
				t.Fatalf("unexpected review: %v, %s", m.viewState, m.sentry.importError)
			}
			if (m.sentry.previewEndpoint != nil) != tc.endpoint {
				t.Fatal("endpoint review differs from file import")
			}
			if m.sentry.envelopeJSON != string(witnessJSON) {
				t.Fatal("paste did not produce the canonical import envelope")
			}
			next, _ = m.handleSentryImportReviewKeys(tea.KeyMsg{Type: tea.KeyEsc})
			m = next.(Model)
			if !m.sentry.importPaste || m.sentry.importJSON != string(tc.data) {
				t.Fatal("back from review lost the pasted document")
			}
			m = m.cancelSentryImport()
			if m.viewState != ViewSentryReferences || m.sentry.importJSON != "" || m.sentry.envelopeJSON != "" || m.sentry.importPaste {
				t.Fatal("cancel did not clear paste state")
			}
		})
	}
}

func TestSentryPasteRejectsInvalidAndOversizedInput(t *testing.T) {
	for _, data := range []string{"", "not JSON", `{"schema":"unknown"}`, `{"schema":"aplane.sentry-enrollment.v1","witness":null}`, strings.Repeat("x", enrollment.MaxEnvelopeBytes+1)} {
		m := Model{}.beginManagerSentryImport()
		m.sentry.importPaste = true
		m.sentry.importName = "lab"
		next, cmd := m.handleSentryImportFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(data), Paste: true})
		m = next.(Model)
		if cmd != nil || len(m.sentry.importJSON) > enrollment.MaxEnvelopeBytes {
			t.Fatal("paste exceeded buffer limit or issued a command")
		}
		m = m.prepareSentryImportReview()
		if m.viewState != ViewSentryImportForm || m.sentry.importError == "" || m.sentry.envelopeJSON != "" {
			t.Fatal("invalid document reached review")
		}
	}
}

func TestSentryPasteRoutesBracketedPasteToNameField(t *testing.T) {
	m := Model{}.beginManagerSentryImport()
	m.sentry.importPaste = true
	m.sentry.importFocus = 1
	m.sentry.importName = "ops-"
	m.sentry.importError = "old error"

	next, cmd := m.handleSentryImportFormKeys(tea.KeyMsg{
		Type: tea.KeyRunes, Runes: []rune("sentry-1"), Paste: true,
	})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	m = next.(Model)
	if m.sentry.importName != "ops-sentry-1" {
		t.Fatalf("importName = %q, want pasted name", m.sentry.importName)
	}
	if m.sentry.importError != "" {
		t.Fatalf("importError = %q, want cleared", m.sentry.importError)
	}
}

func TestSentryImportDefaultFollowsSourceUnlessEdited(t *testing.T) {
	reference := testTUIEnrollmentReference(t)
	data, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	m := Model{sentry: sentryState{importName: "sentry-old", importNameDefault: "sentry-old", importPaste: true}}
	next, _ := m.handleSentryImportFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(string(data)), Paste: true})
	m = next.(Model)
	if m.sentry.importName == "sentry-old" || m.sentry.importName == "" {
		t.Fatal("replacement paste retained stale default")
	}
	m.sentry.importName = "my-sentry"
	next, _ = m.handleSentryImportFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(string(data)), Paste: true})
	if next.(Model).sentry.importName != "my-sentry" {
		t.Fatal("replacement paste overwrote custom name")
	}
	m = Model{sentry: sentryState{importName: "old", importNameDefault: "old", importPath: "/tmp/New.aplane-sentry.json"}}
	m = m.suggestSentryImportNameFromPath()
	if m.sentry.importName != "new" {
		t.Fatal("replacement path retained stale default")
	}
	m.sentry.importName = "custom"
	m.sentry.importPath = "/tmp/another.json"
	m = m.suggestSentryImportNameFromPath()
	if m.sentry.importName != "custom" {
		t.Fatal("replacement path overwrote custom name")
	}
}
