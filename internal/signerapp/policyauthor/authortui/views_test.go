// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
