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
