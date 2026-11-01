// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const newKeyAddress = "GMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZ6LH5CFA"

func TestNewDocumentFromAWorkspaceDocument(t *testing.T) {
	ws, dir := workspace(t, map[string][]byte{"default.json": fixture(t, "signer_default.json"), "ops.json": fixture(t, "signer_key_full.json")})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	m := next.(Model)
	m, _ = press(t, m, "n")
	if m.screen != screenNew || m.newDoc.step != newKey {
		t.Fatalf("n: screen %v step %v", m.screen, m.newDoc.step)
	}
	m = typeText(t, m, "notakey")
	m, _ = press(t, m, "enter")
	if !strings.Contains(view(m), "Algorand address") || m.newDoc.err == "" {
		t.Fatalf("a bad key was not refused:\n%s", view(m))
	}
	m = typeText(t, clearInput(t, m), "default")
	m, _ = press(t, m, "enter")
	if !strings.Contains(m.newDoc.err, "already holds") {
		t.Fatalf("a second default was not refused: %q", m.newDoc.err)
	}
	m = typeText(t, clearInput(t, m), newKeyAddress)
	m, _ = press(t, m, "enter")
	if m.newDoc.step != newStart || !strings.Contains(view(m), "A copy of ops.json") || !strings.Contains(view(m), "shipped signer default") {
		t.Fatalf("starting points:\n%s", view(m))
	}
	for !strings.Contains(view(m), "> A copy of ops.json") {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "enter")
	if m.newDoc.step != newName || m.newDoc.input.Value() != newKeyAddress+".json" {
		t.Fatalf("name step: %q", m.newDoc.input.Value())
	}
	m = typeText(t, clearInput(t, m), "ops.json")
	m, _ = press(t, m, "enter")
	if !strings.Contains(m.newDoc.err, "already exists") {
		t.Fatalf("a taken file name was accepted: %q", m.newDoc.err)
	}
	m = typeText(t, clearInput(t, m), "payroll.json")
	m, _ = press(t, m, "enter")
	if m.screen != screenDocument || filepath.Base(m.file().Path) != "payroll.json" || !m.session().Modified() {
		t.Fatalf("new document: screen %v", m.screen)
	}
	path := filepath.Join(dir, "payroll.json")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the new document was written before a save")
	}
	if got := m.shown().Key; got != newKeyAddress || m.shown().Document == nil || m.shown().Document.MaxFeeMicroAlgos != 10000 {
		t.Fatalf("the new document is not a copy of ops.json under the new key: key %q", got)
	}
	m, _ = press(t, m, "s")
	if !strings.Contains(view(m), "A new file.") {
		t.Fatalf("save review of a new document:\n%s", view(m))
	}
	m, _ = press(t, m, "y")
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), newKeyAddress) || m.session().Modified() {
		t.Fatalf("saving did not create the file: %v", err)
	}
}

func TestNewDocumentInAnEmptyWorkspaceAsksTheRole(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m := next.(Model)
	m, _ = press(t, m, "n")
	if m.newDoc.step != newRole || !strings.Contains(view(m), "Which node role") {
		t.Fatalf("role step:\n%s", view(m))
	}
	m, _ = press(t, m, "right", "enter")
	if m.newDoc.role != "cosigner" || !strings.Contains(view(m), "Witness Key ID") {
		t.Fatalf("role %q\n%s", m.newDoc.role, view(m))
	}
	m = typeText(t, m, "default")
	m, _ = press(t, m, "enter")
	if !strings.Contains(view(m), "Preset deny-all") {
		t.Fatalf("cosigner presets not offered:\n%s", view(m))
	}
	m, _ = press(t, m, "esc")
	if m.screen != screenFiles {
		t.Fatalf("esc returned to %v", m.screen)
	}
	// The new-document screen fits a small terminal at its longest step.
	small, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 50, Height: 10})
	m = small.(Model)
	m, _ = press(t, m, "n", "right", "enter")
	m = typeText(t, m, "default")
	m, _ = press(t, m, "enter")
	for _, line := range strings.Split(m.View(), "\n") {
		if w := lipgloss.Width(line); w > 50 {
			t.Fatalf("line %d wide: %q", w, line)
		}
	}
	if lines := strings.Count(m.View(), "\n") + 1; lines > 10 {
		t.Fatalf("%d lines in a 10-line window", lines)
	}
}
