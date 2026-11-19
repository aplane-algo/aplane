// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/storepaths"
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

// localPassfileModel is a local data directory's model with an appass-file
// helper installed, ready for passphrase entry for set-passfile.
func localPassfileModel(t *testing.T) (Model, string) {
	t.Helper()
	stubSignerStopped(t)
	dataDir := t.TempDir()
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "appass-file"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	svc := &serviceInfo{BinDir: binDir, StoreUID: os.Geteuid(), StoreGID: os.Getegid()}
	m := NewModel(dataDir, svc, true)
	m.viewState = ViewPassphraseInput
	m.currentAction = "set-passfile"
	return m, dataDir
}

// While an action runs, keys do nothing. A second Enter on the confirm
// screen once ran the action again, concurrently, with both entries already
// cleared: the passphrase file ended up empty and appass reported success.
// Esc then q could also quit with the action half done.
func TestKeysAreIgnoredWhileAnActionRuns(t *testing.T) {
	m, dataDir := localPassfileModel(t)
	m, _ = typePassphrase(t, m, typedPassphrase)
	m, _ = press(m, tea.KeyEnter)
	m, _ = typePassphrase(t, m, typedPassphrase)
	m, action := press(m, tea.KeyEnter)
	if action == nil {
		t.Fatal("confirming did not start the action")
	}

	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyEnter},
		{Type: tea.KeyEsc},
		{Type: tea.KeyRunes, Runes: []rune{'q'}},
	} {
		next, cmd := m.Update(key)
		m = next.(Model)
		if cmd != nil || m.quitting || m.viewState == ViewConfirmPassphrase || m.viewState == ViewHome {
			t.Fatalf("%s while the action runs: started a command %v, quitting %v, view %v",
				key, cmd != nil, m.quitting, m.viewState)
		}
	}

	next, _ := m.Update(action())
	m = next.(Model)
	if m.viewState != ViewResult || m.resultError != "" {
		t.Fatalf("after the action: view %v, error %q; want the success screen", m.viewState, m.resultError)
	}
	passphrasePath := filepath.Join(storepaths.NewPaths(dataDir).ProductDir(), "passphrase")
	if got, err := os.ReadFile(passphrasePath); err != nil || string(got) != typedPassphrase {
		t.Fatalf("passphrase file = %q, %v; want the confirmed passphrase", got, err)
	}
}

// Neither setup action accepts an empty passphrase, which could never unlock
// the store, whatever reaches it.
func TestSetActionsRefuseAnEmptyPassphrase(t *testing.T) {
	m, dataDir := localPassfileModel(t)
	if _, err := executeSetPassfile(dataDir, nil, m.svcInfo, true); err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("executeSetPassfile(empty) error = %v, want the empty passphrase refusal", err)
	}
	productDir := storepaths.NewPaths(dataDir).ProductDir()
	for _, name := range []string{"passphrase", "unlock.yaml"} {
		if _, err := os.Lstat(filepath.Join(productDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s after the refusal: %v, want none written", name, err)
		}
	}
	if _, err := executeSetSystemcreds(dataDir, nil, m.svcInfo); err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("executeSetSystemcreds(empty) error = %v, want the empty passphrase refusal", err)
	}
}
