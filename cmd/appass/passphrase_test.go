// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func allZero(b []byte) bool {
	return len(b) > 0 && bytes.Equal(b, make([]byte, len(b)))
}

const typedPassphrase = "correct horse battery staple"

// typePassphrase sends each byte of text as a key and returns every backing
// array the entry outgrew on the way, each in full.
func typePassphrase(t *testing.T, m Model, text string) (Model, [][]byte) {
	t.Helper()
	var outgrown [][]byte
	for _, r := range text {
		before := m.passphraseInput
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = next.(Model)
		if cap(before) > 0 && cap(m.passphraseInput) != cap(before) {
			outgrown = append(outgrown, before[:cap(before)])
		}
	}
	if string(m.passphraseInput) != text {
		t.Fatalf("typed %q, entry holds %q", text, m.passphraseInput)
	}
	if len(outgrown) == 0 {
		t.Fatalf("typing %q never grew the entry", text)
	}
	for i, old := range outgrown {
		if !allZero(old) {
			t.Fatalf("outgrown buffer %d still holds %q", i, old)
		}
	}
	return m, outgrown
}

func press(m Model, key tea.KeyType) (Model, tea.Cmd) {
	next, cmd := m.Update(tea.KeyMsg{Type: key})
	return next.(Model), cmd
}

// Both entries grow without leaving copies behind, and the confirmed
// passphrase is zeroed once the action has run.
func TestPassphraseEntriesAreZeroedAfterUse(t *testing.T) {
	m := NewModel(t.TempDir(), nil, true)
	m.viewState = ViewPassphraseInput
	m.currentAction = "test-no-action"

	m, _ = typePassphrase(t, m, typedPassphrase)
	first := m.passphraseInput[:cap(m.passphraseInput)]
	m, _ = press(m, tea.KeyEnter)
	if m.viewState != ViewConfirmPassphrase {
		t.Fatalf("view = %v, want the confirm screen", m.viewState)
	}

	m, _ = typePassphrase(t, m, typedPassphrase)
	confirmed := m.passphraseInput[:cap(m.passphraseInput)]
	m, cmd := press(m, tea.KeyEnter)
	if cmd == nil {
		t.Fatal("confirming did not start the action")
	}
	if len(m.passphraseInput) != 0 || len(m.passphraseFirst) != 0 || !allZero(first) {
		t.Fatalf("confirming left input %q first %q", m.passphraseInput, first)
	}
	if !bytes.Contains(confirmed, []byte(typedPassphrase)) {
		t.Fatal("the action did not receive the confirmed passphrase")
	}
	cmd()
	if !allZero(confirmed) {
		t.Fatalf("the action left the passphrase as %q", confirmed)
	}
}

// A mismatched confirmation, leaving the form and the end of the program
// each zero what was typed.
func TestPassphraseEntriesAreZeroedOnMismatchEscAndExit(t *testing.T) {
	m := NewModel(t.TempDir(), nil, true)
	m.viewState = ViewPassphraseInput
	m, _ = typePassphrase(t, m, typedPassphrase)
	first := m.passphraseInput[:cap(m.passphraseInput)]
	m, _ = press(m, tea.KeyEnter)

	m, _ = typePassphrase(t, m, "something else entirely")
	mismatched := m.passphraseInput[:cap(m.passphraseInput)]
	m, _ = press(m, tea.KeyEnter)
	if m.passphraseError == "" || len(m.passphraseInput) != 0 || !allZero(mismatched) {
		t.Fatalf("a mismatch left %q (error %q)", mismatched, m.passphraseError)
	}

	m, _ = press(m, tea.KeyEsc)
	if m.viewState != ViewHome || len(m.passphraseFirst) != 0 || !allZero(first) {
		t.Fatalf("leaving the form left the first entry as %q", first)
	}

	m.viewState = ViewPassphraseInput
	m, _ = typePassphrase(t, m, typedPassphrase)
	typed := m.passphraseInput[:cap(m.passphraseInput)]
	m.clearPassphrases()
	if !allZero(typed) {
		t.Fatalf("clearing at exit left %q", typed)
	}
}
