// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// selectField moves the cursor onto the field at pointer.
func selectField(t *testing.T, m Model, pointer string) Model {
	t.Helper()
	for si, s := range m.sections {
		for fi, f := range s.Fields {
			if f.Pointer == pointer {
				m.sectionCursor, m.fieldCursor, m.focus = si, fi, paneForm
				return m
			}
		}
	}
	t.Fatalf("no field %s", pointer)
	return m
}

func typeText(t *testing.T, m Model, text string) Model {
	t.Helper()
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text)})
	return next.(Model)
}

func clearInput(t *testing.T, m Model) Model {
	t.Helper()
	for i := 0; i < 200; i++ {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
		m = next.(Model)
	}
	return m
}

func editModel(t *testing.T, name string) (Model, string) {
	t.Helper()
	ws, dir := workspace(t, map[string][]byte{"ops.json": fixture(t, name)})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	return next.(Model), filepath.Join(dir, "ops.json")
}

func TestToggleAndChoiceEdits(t *testing.T) {
	m, path := editModel(t, "signer_key_full.json")
	m = selectField(t, m, "/reject_close_remainder")
	m, _ = press(t, m, " ")
	if node := m.session().Current().Draft.At("/reject_close_remainder"); !node.Bool() {
		t.Fatal("space did not toggle the guard on")
	}
	if !strings.Contains(view(m), "modified") {
		t.Fatal("the header does not say modified")
	}
	m = selectField(t, m, "/transfer_policy/on_no_route")
	m, _ = press(t, m, "enter")
	if m.prompt.kind != promptChoice || !strings.Contains(view(m), "operator_default") {
		t.Fatalf("enter on a choice: prompt %v\n%s", m.prompt.kind, view(m))
	}
	m, _ = press(t, m, "right", "enter")
	if got := m.session().Current().Draft.At("/transfer_policy/on_no_route").Text(); got != "review" {
		t.Fatalf("on_no_route = %q, want review", got)
	}
	if disk, _ := os.ReadFile(path); !bytes.Equal(disk, fixture(t, "signer_key_full.json")) {
		t.Fatal("editing wrote to disk before a save")
	}
}

func TestTypedEditsAndValidation(t *testing.T) {
	m, _ := editModel(t, "signer_key_full.json")
	m = selectField(t, m, "/max_fee_microalgos")
	m, _ = press(t, m, "enter")
	if m.prompt.kind != promptEdit || m.prompt.input.Value() != "0.01" || !strings.Contains(view(m), "6 decimals (builtin)") {
		t.Fatalf("fee editor: %q\n%s", m.prompt.input.Value(), view(m))
	}
	m = typeText(t, clearInput(t, m), "1.0000001")
	if !strings.Contains(view(m), "decimal places") {
		t.Fatalf("no live error for too many decimals:\n%s", view(m))
	}
	m, _ = press(t, m, "enter")
	if m.prompt.kind == promptNone {
		t.Fatal("an invalid amount was accepted")
	}
	m = typeText(t, clearInput(t, m), "0.5")
	m, _ = press(t, m, "enter")
	if got := m.session().Current().Document.MaxFeeMicroAlgos; got != 500000 {
		t.Fatalf("fee = %d, want 500000", got)
	}

	m = selectField(t, m, "/transfer_policy/routes/1/sources")
	m, _ = press(t, m, "enter")
	m = typeText(t, clearInput(t, m), "@treasury, NOTANADDRESS")
	if !strings.Contains(view(m), "not a valid address") {
		t.Fatalf("no live error for a bad term:\n%s", view(m))
	}
	m, _ = press(t, m, "esc")
	if m.prompt.kind != promptNone || m.session().Current().Draft.At("/transfer_policy/routes/1/sources/1").Exists() {
		t.Fatal("esc did not cancel the edit")
	}
}

func TestAddRemoveUndoRedo(t *testing.T) {
	m, _ := editModel(t, "signer_key_minimal.json")
	for m.sections[m.sectionCursor].ID != "routes" {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "a")
	if m.prompt.kind != promptAdd || m.prompt.picking {
		t.Fatalf("a on routes: %+v", m.prompt)
	}
	m = typeText(t, m, "payouts")
	m, _ = press(t, m, "enter")
	if !m.session().Current().Draft.At("/transfer_policy/routes/0/id").Exists() {
		t.Fatal("route not added")
	}
	if out := view(m); !strings.Contains(out, "Route payouts") || !strings.Contains(out, "✗") {
		t.Fatalf("the new, empty route is not shown with its problems:\n%s", out)
	}

	// Remove the route from the outline, then undo and redo.
	for m.sections[m.sectionCursor].ID != "route:0" {
		m, _ = press(t, m, "down")
	}
	m.focus = paneOutline
	m, _ = press(t, m, "d")
	if m.prompt.kind != promptRemove {
		t.Fatal("d did not ask to confirm")
	}
	m, _ = press(t, m, "y")
	if m.session().Current().Draft.At("/transfer_policy/routes/0").Exists() {
		t.Fatal("route not removed")
	}
	m, _ = press(t, m, "u")
	if !m.session().Current().Draft.At("/transfer_policy/routes/0").Exists() {
		t.Fatal("undo did not restore the route")
	}
	m, _ = press(t, m, "ctrl+r")
	if m.session().Current().Draft.At("/transfer_policy/routes/0").Exists() {
		t.Fatal("redo did not remove the route again")
	}
	m, _ = press(t, m, "u", "u")
	if m.session().Modified() {
		t.Fatal("undoing every edit left the file modified")
	}

	// A section with several add actions offers a choice first.
	for m.sections[m.sectionCursor].ID != "address_sets" {
		m, _ = press(t, m, "up")
	}
	m, _ = press(t, m, "a")
	if m.prompt.kind != promptAdd || (len(m.prompt.adds) > 1) != m.prompt.picking {
		t.Fatalf("add picker: %+v", m.prompt)
	}
}

func TestUnparsableFileIsReadOnlyAndReloadKeepsEdits(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"bad.json": []byte("{"), "ok.json": fixture(t, "signer_default.json")})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m := next.(Model)
	m, _ = press(t, m, "enter", "a")
	if m.prompt.kind != promptNone || !strings.Contains(view(m), "cannot be edited here") || !strings.Contains(view(m), "read-only") {
		t.Fatalf("unparsable file:\n%s", view(m))
	}
	m, _ = press(t, m, "esc", "down", "enter")
	m = selectField(t, m, "/reject_clawback")
	m, _ = press(t, m, " ", "r")
	if !strings.Contains(view(m), "unsaved edits") || !m.session().Modified() {
		t.Fatalf("reload with unsaved edits:\n%s", view(m))
	}
	m, _ = press(t, m, "esc", "esc")
	if !strings.Contains(view(m), "(modified)") {
		t.Fatalf("files screen does not mark the edited file:\n%s", view(m))
	}
}

// TestEditBarFitsTheTerminal: with the edit bar open, the screen still fits.
func TestEditBarFitsTheTerminal(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"ops.json": fixture(t, "signer_key_full.json")})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 70, Height: 18})
	m := next.(Model)
	m = selectField(t, m, "/max_fee_microalgos")
	m, _ = press(t, m, "enter")
	m = typeText(t, clearInput(t, m), "x")
	if lines := strings.Count(m.View(), "\n") + 1; lines > 18 {
		t.Fatalf("%d lines in an 18-line window:\n%s", lines, view(m))
	}
}

func TestCopyInTheTUI(t *testing.T) {
	m, _ := editModel(t, "signer_key_full.json")
	for m.sections[m.sectionCursor].ID != "route:1" {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "C")
	if m.prompt.kind != promptAdd || !strings.Contains(view(m), "id for the copy") {
		t.Fatalf("C on a route:\n%s", view(m))
	}
	m = typeText(t, m, "ops-topup-2")
	m, _ = press(t, m, "enter")
	if m.session().Current().Draft.At("/transfer_policy/routes/2/id").Text() != "ops-topup-2" || !strings.Contains(view(m), "Route ops-topup-2") {
		t.Fatalf("route copy:\n%s", view(m))
	}
	m = selectField(t, m, "/transfer_policy/blocked_destinations/0")
	m, _ = press(t, m, "C")
	if len(m.session().Current().Draft.At("/transfer_policy/blocked_destinations").Items()) != 2 {
		t.Fatal("C did not duplicate the address")
	}
	m = selectField(t, m, "/max_fee_microalgos")
	m, _ = press(t, m, "C")
	if !strings.Contains(view(m), "Nothing to copy here") {
		t.Fatal("C on a field with nothing to copy did not say so")
	}
}

func TestTabCyclesSuggestions(t *testing.T) {
	m, _ := editModel(t, "signer_key_full.json")
	m = selectField(t, m, "/transfer_policy/routes/1/destinations")
	m, _ = press(t, m, "enter")
	if !strings.Contains(view(m), "tab: *, self") {
		t.Fatalf("the edit bar does not offer suggestions:\n%s", view(m))
	}
	start := m.prompt.input.Value()
	m, _ = press(t, m, "tab")
	if got := m.prompt.input.Value(); got != start+", *" {
		t.Fatalf("first tab: %q, want %q", got, start+", *")
	}
	m, _ = press(t, m, "tab")
	if got := m.prompt.input.Value(); got != start+", self" {
		t.Fatalf("second tab replaces the suggestion: %q", got)
	}
	m = typeText(t, m, "x")
	m, _ = press(t, m, "tab")
	if got := m.prompt.input.Value(); !strings.HasPrefix(got, start+", selfx, ") {
		t.Fatalf("typing ended the cycle, so tab appends: %q", got)
	}
	m = typeText(t, clearInput(t, m), "@ops")
	m, _ = press(t, m, "tab", "tab", "enter")
	if got := compact(m, "/transfer_policy/routes/1/destinations"); got != `["@ops", "self"]` {
		t.Fatalf("destinations = %s", got)
	}

	m = selectField(t, m, "/transfer_policy/blocked_destinations/0")
	m, _ = press(t, m, "enter", "tab")
	if got := m.prompt.input.Value(); strings.Contains(got, ",") {
		t.Fatalf("a single-term field got a list: %q", got)
	}
}

func compact(m Model, pointer string) string {
	n := m.session().Current().Draft.At(pointer)
	var parts []string
	for _, item := range n.Items() {
		parts = append(parts, `"`+item.Text()+`"`)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
