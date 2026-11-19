// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"strings"
	"testing"
)

// A policy file and its name can hold terminal control sequences and
// bidirectional controls: a JSON string decodes \u001b to a raw ESC. Each
// screen shows them as escapes.

// evilDocument is the signer key fixture with a description that holds a
// clear-screen sequence and a right-to-left override, and with extra members
// added after it.
func evilDocument(t *testing.T, extra string) []byte {
	t.Helper()
	doc := strings.Replace(string(fixture(t, "signer_key_full.json")),
		`"description": "Operations key"`,
		`"description": "Ops\u001b[2J key\u202e"`+extra, 1)
	if doc == string(fixture(t, "signer_key_full.json")) {
		t.Fatal("the fixture has no description to replace")
	}
	return []byte(doc)
}

const evilName = "ops\x1b[2J\u202e.json"

func assertNoRawControls(t *testing.T, what, rendered string, wantEscaped ...string) {
	t.Helper()
	for _, raw := range []string{"\x1b", "\a", "\u202e"} {
		if strings.Contains(rendered, raw) {
			t.Fatalf("%s shows a raw %q:\n%s", what, raw, rendered)
		}
	}
	for _, want := range wantEscaped {
		if !strings.Contains(rendered, want) {
			t.Fatalf("%s lacks the escaped %q:\n%s", what, want, rendered)
		}
	}
}

func TestScreensEscapePolicyFileText(t *testing.T) {
	m := sizedModel(t, map[string][]byte{evilName: evilDocument(t, ""), "b.json": fixture(t, "signer_default.json")}, 200, 60)
	assertNoRawControls(t, "files screen", m.filesView(), `ops\x1b[2J\u202e.json`)

	m, _ = press(t, m, "down", "enter")
	if m.screen != screenDocument {
		t.Fatalf("enter opened screen %v", m.screen)
	}
	assertNoRawControls(t, "document", m.documentView(), `ops\x1b[2J\u202e.json`)
	m = selectField(t, m, "/description")
	lines, _ := m.formLines(150)
	assertNoRawControls(t, "form", strings.Join(lines, "\n"), `Ops\x1b[2J key\u202e`)
	assertNoRawControls(t, "outline", strings.Join(m.outlineLines(40), "\n"))

	explain, _ := press(t, m, "x")
	if explain.screen != screenExplain {
		t.Fatalf("x opened screen %v (status %q)", explain.screen, explain.status)
	}
	assertNoRawControls(t, "explain", explain.pageView(), `Explain ops\x1b[2J\u202e.json`)

	field, _ := press(t, m, "v")
	assertNoRawControls(t, "field page", field.pageView(), `Ops\x1b[2J key\u202e`)

	compare, _ := press(t, m, "c")
	if compare.screen == screenComparePick {
		compare, _ = press(t, compare, "enter")
	}
	assertNoRawControls(t, "compare", compare.pageView(), `ops\x1b[2J\u202e.json`)

	m.status = "Saved " + evilName
	assertNoRawControls(t, "status line", m.statusText(), `Saved ops\x1b[2J\u202e.json`)

	// An unknown member's name is in the problem's pointer.
	unknown := sizedModel(t, map[string][]byte{"ops.json": evilDocument(t, `, "zz\u001b]0;x\u0007": 1`)}, 200, 60)
	problems, _ := press(t, unknown, "p")
	assertNoRawControls(t, "problems", problems.problemsView(), `zz\x1b]0;x\a`)
	lines, _ = unknown.formLines(150)
	for _, s := range unknown.sections {
		for _, p := range s.Problems {
			lines = append(lines, unknown.problemLines(p, 150)...)
		}
	}
	assertNoRawControls(t, "problem lines", strings.Join(lines, "\n"))
}

// The edit bar shows the value being edited as it is; View still escapes it.
func TestViewEscapesTheValueBeingEdited(t *testing.T) {
	m := sizedModel(t, map[string][]byte{"ops.json": evilDocument(t, "")}, 200, 60)
	m = selectField(t, m, "/description")
	m, _ = press(t, m, "enter")
	if m.prompt.kind != promptEdit {
		t.Fatalf("enter on the description opened prompt %v", m.prompt.kind)
	}
	assertNoRawControls(t, "View while editing", m.View(), `Ops\x1b[2J key\u202e`)
}
