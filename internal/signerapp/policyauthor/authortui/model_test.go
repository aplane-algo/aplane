// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "test", "contracts", "policy", "v1", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func workspace(t *testing.T, files map[string][]byte) (*policyauthor.Workspace, string) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ws, err := policyauthor.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ws, dir
}

func press(t *testing.T, m Model, keys ...string) (Model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "up":
			msg = tea.KeyMsg{Type: tea.KeyUp}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		next, c := m.Update(msg)
		m, cmd = next.(Model), c
	}
	return m, cmd
}

func quits(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func view(m Model) string { return ansi.Strip(m.View()) }

func TestOneFileOpensStraightOnTheDocument(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"ops.json": fixture(t, "signer_key_full.json")})
	m := New(ws, asa.BuiltinMetadata, nil)
	if m.screen != screenDocument {
		t.Fatalf("screen = %v, want the document", m.screen)
	}
	out := view(m)
	for _, want := range []string{"ops.json", "signer", "Summary", "Guards", "Routes (5)", "Route treasury-to-ops", "Format", "aplane.policy.v1", "1 warning(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("view lacks %q:\n%s", want, out)
		}
	}
	if _, cmd := press(t, m, "esc"); !quits(cmd) {
		t.Fatal("esc on a one-file workspace does not quit")
	}
}

func TestFilesScreenAndNavigation(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{
		"default.json": fixture(t, "signer_default.json"),
		"zbad.json":    fixture(t, "semantic_invalid/signer_route_unknown_address_set.json"),
	})
	sized, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	m := sized.(Model)
	if m.screen != screenFiles || !strings.Contains(view(m), "zbad.json") || !strings.Contains(view(m), "1 error(s)") {
		t.Fatalf("files screen:\n%s", view(m))
	}
	m, _ = press(t, m, "down", "enter")
	if m.screen != screenDocument || filepath.Base(m.file().Path) != "zbad.json" {
		t.Fatalf("enter opened %v", m.screen)
	}
	if out := view(m); !strings.Contains(out, "✗1") || !strings.Contains(out, "1 error(s)") {
		t.Fatalf("the outline does not mark the error:\n%s", out)
	}

	// Move to the section holding the error and into its form.
	target := -1
	for i, s := range m.sections {
		if _, errs := s.ProblemCount(); errs > 0 {
			target = i
		}
	}
	for m.sectionCursor < target {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "enter")
	if m.focus != paneForm {
		t.Fatal("enter did not move into the form")
	}
	if out := view(m); !strings.Contains(out, `unknown address set "nobody"`) {
		t.Fatalf("the form does not show the problem:\n%s", out)
	}
	m, _ = press(t, m, "down", "down")
	if m.fieldCursor != 2 {
		t.Fatalf("field cursor = %d", m.fieldCursor)
	}
	m, _ = press(t, m, "tab")
	if m.focus != paneOutline || m.fieldCursor != 2 {
		t.Fatalf("tab: focus %v field %d", m.focus, m.fieldCursor)
	}
	m, _ = press(t, m, "up")
	if m.fieldCursor != 0 {
		t.Fatal("changing section kept the field cursor")
	}
	m, _ = press(t, m, "esc")
	if m.screen != screenFiles || m.fileCursor != 1 {
		t.Fatalf("esc: screen %v cursor %d", m.screen, m.fileCursor)
	}
	if _, cmd := press(t, m, "q"); !quits(cmd) {
		t.Fatal("q does not quit")
	}
}

func TestUnparsableAndMissingAreShown(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{
		"broken.json":  []byte(`{"format": `),
		"partial.json": []byte(`{"format": "aplane.policy.v1", "role": "signer", "key": "default"}`),
	})
	m := New(ws, nil, nil)
	m, _ = press(t, m, "enter")
	if out := view(m); !strings.Contains(out, "File (unparsable)") || !strings.Contains(out, "invalid JSON") {
		t.Fatalf("unparsable file:\n%s", out)
	}
	m, _ = press(t, m, "esc", "down", "enter", "down", "enter")
	if out := view(m); !strings.Contains(out, "(missing)") || !strings.Contains(out, "missing required field") {
		t.Fatalf("missing fields:\n%s", out)
	}
}

func TestReloadFollowsTheDisk(t *testing.T) {
	ws, dir := workspace(t, map[string][]byte{"a.json": fixture(t, "signer_default.json"), "b.json": fixture(t, "signer_key_full.json")})
	m := New(ws, nil, nil)
	m, _ = press(t, m, "enter")
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ = press(t, m, "r")
	if m.screen != screenDocument || m.file().State != policyauthor.StateUnparsable || !strings.Contains(view(m), "Reloaded from disk") {
		t.Fatalf("reload: screen %v state %s\n%s", m.screen, m.file().State, view(m))
	}
	if err := os.Remove(filepath.Join(dir, "a.json")); err != nil {
		t.Fatal(err)
	}
	m, _ = press(t, m, "r")
	if m.screen != screenFiles || !strings.Contains(view(m), "no longer in the workspace") {
		t.Fatalf("reload after delete: screen %v\n%s", m.screen, view(m))
	}
}

func TestDiagnosticsShowInTheStatusLine(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"a.json": fixture(t, "signer_default.json")})
	diags := []string{"warning: the signer's ASA cache is unusable"}
	if out := view(New(ws, nil, &diags)); !strings.Contains(out, "ASA cache is unusable") {
		t.Fatalf("diagnostic not shown:\n%s", out)
	}
}

// TestViewFitsTheTerminal: no rendered line is wider than the window.
func TestViewFitsTheTerminal(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{
		"ops.json":      fixture(t, "signer_key_full.json"),
		"cosigner.json": fixture(t, "cosigner_key_full.json"),
	})
	for _, size := range [][2]int{{60, 20}, {100, 30}, {160, 50}} {
		next, _ := New(ws, asa.BuiltinMetadata, nil).Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m := next.(Model)
		check := func(where string) {
			for _, line := range strings.Split(m.View(), "\n") {
				if w := lipgloss.Width(line); w > size[0] {
					t.Fatalf("%dx%d %s: line is %d wide: %q", size[0], size[1], where, w, ansi.Strip(line))
				}
			}
			if lines := strings.Count(m.View(), "\n") + 1; lines > size[1]+1 {
				t.Fatalf("%dx%d %s: %d lines", size[0], size[1], where, lines)
			}
		}
		check("files")
		m, _ = press(t, m, "down", "enter")
		for range m.sections {
			check("outline")
			m, _ = press(t, m, "down")
		}
		m, _ = press(t, m, "enter")
		for i := 0; i < 30; i++ {
			check("form")
			m, _ = press(t, m, "down")
		}
	}
}
