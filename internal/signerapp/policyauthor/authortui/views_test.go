// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func sizedModel(t *testing.T, files map[string][]byte, w, h int) Model {
	t.Helper()
	ws, _ := workspace(t, files)
	next, _ := New(ws, asa.BuiltinMetadata, nil).Update(tea.WindowSizeMsg{Width: w, Height: h})
	return next.(Model)
}

// twoProblems is a signer document with an unknown field and a missing
// required one: two errors in different sections.
func twoProblems(t *testing.T) []byte {
	doc := strings.Replace(string(fixture(t, "signer_key_minimal.json")), `"reject_clawback": false,`, `"zz_extra": 1,`, 1)
	return []byte(doc)
}

func TestJumpBetweenProblemsWraps(t *testing.T) {
	m := sizedModel(t, map[string][]byte{"a.json": twoProblems(t)}, 160, 40)
	locs := m.problemLocations()
	if len(locs) == 0 {
		t.Fatal("no problems to jump to")
	}
	m, _ = press(t, m, "]")
	if m.sectionCursor != locs[0].section || (locs[0].field >= 0 && (m.focus != paneForm || m.fieldCursor != locs[0].field)) {
		t.Fatalf("] went to section %d field %d, want %+v", m.sectionCursor, m.fieldCursor, locs[0])
	}
	for range locs {
		m, _ = press(t, m, "]")
	}
	if m.sectionCursor != locs[0].section {
		t.Fatal("] did not wrap to the first problem")
	}
	m, _ = press(t, m, "[")
	last := locs[len(locs)-1]
	if m.sectionCursor != last.section {
		t.Fatalf("[ from the first problem went to section %d, want the last (%d)", m.sectionCursor, last.section)
	}

	clean := sizedModel(t, map[string][]byte{"ok.json": fixture(t, "signer_default.json")}, 120, 30)
	clean, _ = press(t, clean, "]")
	if !strings.Contains(view(clean), "No problems in this file") {
		t.Fatal("] on a clean file did not say so")
	}
}

func TestProblemsListJumpsToAProblem(t *testing.T) {
	m := sizedModel(t, map[string][]byte{"a.json": fixture(t, "semantic_invalid/signer_route_unknown_address_set.json")}, 160, 40)
	m, _ = press(t, m, "p")
	if m.screen != screenProblems || !strings.Contains(view(m), `unknown address set "nobody"`) || !strings.Contains(view(m), "Route r › Sources") {
		t.Fatalf("problems list:\n%s", view(m))
	}
	m, _ = press(t, m, "enter")
	if m.screen != screenDocument || m.focus != paneForm || m.sections[m.sectionCursor].Fields[m.fieldCursor].Label != "Sources" {
		t.Fatalf("enter went to %v %q", m.screen, m.sections[m.sectionCursor].Title)
	}
}

func TestExplainView(t *testing.T) {
	m := sizedModel(t, map[string][]byte{"ops.json": fixture(t, "signer_key_full.json")}, 160, 40)
	m, _ = press(t, m, "x")
	if m.screen != screenExplain || !strings.Contains(view(m), "Signer key document for") {
		t.Fatalf("explain:\n%s", view(m))
	}
	m, _ = press(t, m, "G")
	if m.page.offset == 0 && len(m.page.lines) > m.pageHeight() {
		t.Fatal("end did not scroll")
	}
	m, _ = press(t, m, "esc")
	if m.screen != screenDocument {
		t.Fatal("esc did not return to the document")
	}

	bad := sizedModel(t, map[string][]byte{"bad.json": fixture(t, "semantic_invalid/signer_route_unknown_address_set.json")}, 120, 30)
	bad, _ = press(t, bad, "x")
	if bad.screen != screenDocument || !strings.Contains(view(bad), "Explain needs a valid document") {
		t.Fatalf("explain of an invalid file: screen %v\n%s", bad.screen, view(bad))
	}
}

func TestCompareWithTheWorkspaceDefaultAndAPickedFile(t *testing.T) {
	looser := strings.Replace(string(fixture(t, "signer_key_full.json")), `"max_fee_microalgos": "10000"`, `"max_fee_microalgos": "50000"`, 1)
	m := sizedModel(t, map[string][]byte{
		"default.json": fixture(t, "signer_default.json"),
		"ops.json":     fixture(t, "signer_key_full.json"),
		"ops2.json":    []byte(looser),
	}, 160, 40)
	m, _ = press(t, m, "down", "enter", "c")
	if flat := strings.Join(strings.Fields(view(m)), " "); m.screen != screenCompare || !strings.Contains(flat, "compared with the workspace default (default.json), by policy") || !strings.Contains(flat, "replaces the default wholesale") {
		t.Fatalf("compare with the default:\n%s", view(m))
	}
	m, _ = press(t, m, "o")
	if m.screen != screenComparePick || strings.Contains(view(m), "> ops.json") {
		t.Fatalf("picker (must not offer the open file first):\n%s", view(m))
	}
	for !strings.Contains(view(m), "> ops2.json") {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "enter")
	if out := view(m); m.screen != screenCompare || !strings.Contains(out, "compared with ops2.json") || !strings.Contains(out, "tightened") || !strings.Contains(out, "/max_fee_microalgos") {
		t.Fatalf("compare with a picked file:\n%s", out)
	}

	// The default itself picks a file; a lone file has nothing to compare.
	m, _ = press(t, m, "esc", "esc", "up", "enter", "c")
	if m.screen != screenComparePick {
		t.Fatalf("c on the default: screen %v", m.screen)
	}
	one := sizedModel(t, map[string][]byte{"a.json": fixture(t, "signer_default.json")}, 120, 30)
	one, _ = press(t, one, "c")
	if one.screen != screenDocument || !strings.Contains(view(one), "Nothing to compare with") {
		t.Fatalf("compare in a one-file workspace:\n%s", view(one))
	}
}

func TestHelpAndPagesFitTheTerminal(t *testing.T) {
	m := sizedModel(t, map[string][]byte{"default.json": fixture(t, "signer_default.json"), "ops.json": fixture(t, "signer_key_full.json")}, 60, 16)
	m, _ = press(t, m, "down", "enter")
	for _, key := range []string{"?", "x", "c", "p"} {
		page, _ := press(t, m, key)
		if page.screen == screenDocument {
			t.Fatalf("%s did not open a page", key)
		}
		for _, line := range strings.Split(page.View(), "\n") {
			if w := lipgloss.Width(line); w > 60 {
				t.Fatalf("%s: line %d wide: %q", key, w, line)
			}
		}
		if lines := strings.Count(page.View(), "\n") + 1; lines > 17 {
			t.Fatalf("%s: %d lines in a 16-line window", key, lines)
		}
		if key == "?" && !strings.Contains(strings.Join(page.page.lines, "\n"), "never contacts a node") {
			t.Fatal("help does not say appolicy never contacts a node")
		}
	}
}

// TestEmptyProblemsListIgnoresMoves: a clean file's problems list takes
// up/down/enter without moving the cursor out of range.
func TestEmptyProblemsListIgnoresMoves(t *testing.T) {
	m := sizedModel(t, map[string][]byte{"a.json": fixture(t, "signer_default.json")}, 120, 30)
	m, _ = press(t, m, "p", "down", "enter", "up", "enter")
	if m.screen != screenProblems || m.problemCursor != 0 || !strings.Contains(view(m), "No problems.") {
		t.Fatalf("screen %v cursor %d\n%s", m.screen, m.problemCursor, view(m))
	}
	bad := sizedModel(t, map[string][]byte{"b.json": fixture(t, "semantic_invalid/signer_route_unknown_address_set.json")}, 120, 30)
	bad, _ = press(t, bad, "p", "down", "down", "up", "up", "up")
	if bad.problemCursor != 0 {
		t.Fatalf("cursor = %d after moving past both ends of a one-item list", bad.problemCursor)
	}
}

// TestLongListsFollowTheCursor: the files screen and the compare picker show
// the selected row however many files there are.
func TestLongListsFollowTheCursor(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 35; i++ {
		files[fmt.Sprintf("f%02d.json", i)] = fixture(t, "signer_default.json")
	}
	m := sizedModel(t, files, 100, 16)
	fits := func(where string) {
		t.Helper()
		if lines := strings.Count(m.View(), "\n") + 1; lines > 16 {
			t.Fatalf("%s: %d lines in a 16-line window", where, lines)
		}
		if !strings.Contains(view(m), "> ") {
			t.Fatalf("%s: the selected row is not shown:\n%s", where, view(m))
		}
	}
	fits("files at the top")
	for i := 0; i < 34; i++ {
		m, _ = press(t, m, "down")
	}
	fits("files at the bottom")
	if !strings.Contains(view(m), "> f34.json") {
		t.Fatalf("last file not shown as selected:\n%s", view(m))
	}
	m, _ = press(t, m, "enter", "c")
	fits("picker at the top")
	for i := 0; i < 34; i++ {
		m, _ = press(t, m, "down")
	}
	fits("picker at the bottom")
	if !strings.Contains(view(m), "> f33.json") {
		t.Fatalf("last pickable file not shown as selected:\n%s", view(m))
	}
}

// TestLongFieldValuesAreReadableInFull: v on a field opens it in full.
func TestLongFieldValuesAreReadableInFull(t *testing.T) {
	long := strings.Repeat("treasury policy note ", 45) + "END-OF-DESCRIPTION"
	doc := strings.Replace(string(fixture(t, "signer_key_full.json")), `"description": "Operations key"`, `"description": "`+long+`"`, 1)
	m := sizedModel(t, map[string][]byte{"a.json": []byte(doc)}, 80, 16)
	m, _ = press(t, m, "enter", "down", "down", "down")
	if label := m.sections[m.sectionCursor].Fields[m.fieldCursor].Label; label != "Description" {
		t.Fatalf("cursor on %q", label)
	}
	m, _ = press(t, m, "v")
	if m.screen != screenField {
		t.Fatalf("v in the form opened screen %v", m.screen)
	}
	if body := strings.Join(m.page.lines, " "); !strings.Contains(body, "END-OF-DESCRIPTION") || !strings.Contains(body, "/description") {
		t.Fatal("the field page does not hold the whole value")
	}
	m, _ = press(t, m, "G")
	if !strings.Contains(view(m), "END-OF-DESCRIPTION") {
		t.Fatalf("the end of the value is not reachable:\n%s", view(m))
	}
	m, _ = press(t, m, "esc")
	if m.screen != screenDocument || m.focus != paneForm {
		t.Fatalf("esc returned to %v", m.screen)
	}
}

// TestRekeyEdgesShowWholeAddresses: a rekey edge's sender and targets are
// values, wrapped rather than cut, not truncated labels.
func TestRekeyEdgesShowWholeAddresses(t *testing.T) {
	m := sizedModel(t, map[string][]byte{"c.json": fixture(t, "cosigner_key_full.json")}, 100, 40)
	for m.sections[m.sectionCursor].ID != "rekey" {
		m, _ = press(t, m, "down")
	}
	lines, _ := m.formLines(40)
	joined := strings.ReplaceAll(ansi.Strip(strings.Join(lines, "")), " ", "")
	if !strings.Contains(joined, "Edge1senderCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM") || !strings.Contains(joined, "@new_auth") {
		t.Fatalf("rekey edge not laid out in full: %q", joined)
	}
	if out := view(m); !strings.Contains(out, "EI7JH2AYM") {
		t.Fatalf("the end of the sender is not on screen:\n%s", out)
	}
}

// TestEmptyWorkspaceKeysAndReload: moving in an empty workspace and then
// reloading after a file appears leaves the cursor on a real row.
func TestEmptyWorkspaceKeysAndReload(t *testing.T) {
	ws, dir := workspace(t, map[string][]byte{})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	m := next.(Model)
	m, _ = press(t, m, "down", "up", "down", "enter")
	if m.screen != screenFiles || m.fileCursor != 0 || !strings.Contains(view(m), "No policy files.") {
		t.Fatalf("empty workspace: screen %v cursor %d", m.screen, m.fileCursor)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.json"), fixture(t, "signer_default.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ = press(t, m, "r", "enter")
	if m.screen != screenDocument || filepath.Base(m.file().Path) != "a.json" {
		t.Fatalf("after reload and enter: screen %v", m.screen)
	}
}
