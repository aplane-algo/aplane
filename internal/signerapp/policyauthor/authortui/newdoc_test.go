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

// TestNewDocumentReviewIdentityAndCopies covers a new key document's save
// review against the workspace default, an unsaved new default counting as
// the workspace's default and role, and a copy taking a document's unsaved
// edits.
func TestNewDocumentReviewIdentityAndCopies(t *testing.T) {
	strict := strings.Replace(string(fixture(t, "signer_default.json")), `"max_fee_microalgos": "0"`, `"max_fee_microalgos": "5000"`, 1)
	ws, _ := workspace(t, map[string][]byte{"default.json": []byte(strict)})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	m := next.(Model)

	// A key document from the shipped default loosens the workspace default's
	// fee cap; the save review says so.
	m, _ = press(t, m, "n")
	m = typeText(t, m, newKeyAddress)
	m, _ = press(t, m, "enter", "enter", "enter")
	m, _ = press(t, m, "s")
	if out := strings.Join(strings.Fields(strings.Join(m.page.lines, " ")), " "); !strings.Contains(out, "the workspace default (default.json)") || !strings.Contains(out, "loosened /max_fee_microalgos") {
		t.Fatalf("new key document review:\n%s", out)
	}

	// In an empty workspace: the first new document sets the role, and an
	// unsaved default counts.
	empty, _ := workspace(t, map[string][]byte{})
	next, _ = New(empty, nil, nil).Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	e := next.(Model)
	e, _ = press(t, e, "n", "enter")
	e = typeText(t, e, "default")
	e, _ = press(t, e, "enter", "enter", "enter")
	e, _ = press(t, e, "s")
	if out := strings.Join(m.page.lines, " ") + strings.Join(e.page.lines, " "); !strings.Contains(out, "nothing to compare it with") {
		t.Fatalf("new default review:\n%s", strings.Join(e.page.lines, "\n"))
	}
	e, _ = press(t, e, "esc", "n")
	if e.newDoc.step != newKey || e.newDoc.role != "signer" {
		t.Fatalf("second new document: step %v role %q (the workspace role was not kept)", e.newDoc.step, e.newDoc.role)
	}
	e = typeText(t, e, "default")
	e, _ = press(t, e, "enter")
	if !strings.Contains(e.newDoc.err, "already holds") {
		t.Fatalf("a second unsaved default was accepted: %q", e.newDoc.err)
	}

	// A copy takes the source document's unsaved edits.
	ws2, _ := workspace(t, map[string][]byte{"ops.json": fixture(t, "signer_key_full.json")})
	next, _ = New(ws2, nil, nil).Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	c := next.(Model)
	c = selectField(t, c, "/max_fee_microalgos")
	c, _ = press(t, c, "enter")
	c = typeText(t, clearInput(t, c), "0.5")
	c, _ = press(t, c, "enter", "n")
	c = typeText(t, c, newKeyAddress)
	c, _ = press(t, c, "enter")
	for !strings.Contains(view(c), "> A copy of ops.json") {
		c, _ = press(t, c, "down")
	}
	c, _ = press(t, c, "enter", "enter")
	if fee := c.shown().Document.MaxFeeMicroAlgos; fee != 500000 {
		t.Fatalf("copy fee = %d, want the unsaved 500000", fee)
	}
}
