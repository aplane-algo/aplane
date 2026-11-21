// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const externalFixture = "cosigner_key_external_checks.json"

// TestExternalSectionsFitTheTerminal walks every section and field of a
// document with external checks at 80x24, the smallest supported window, and
// with a rule's editor open.
func TestExternalSectionsFitTheTerminal(t *testing.T) {
	const width, height = 80, 24
	ws, _ := workspace(t, map[string][]byte{"cosigner.json": fixture(t, externalFixture)})
	next, _ := New(ws, asa.BuiltinMetadata, nil).Update(tea.WindowSizeMsg{Width: width, Height: height})
	m := next.(Model)
	check := func(where string) {
		t.Helper()
		out := m.View()
		for _, line := range strings.Split(out, "\n") {
			if w := lipgloss.Width(line); w > width {
				t.Fatalf("%s: line is %d wide: %q", where, w, ansi.Strip(line))
			}
		}
		if lines := strings.Count(out, "\n") + 1; lines > height+1 {
			t.Fatalf("%s: %d lines", where, lines)
		}
	}
	seen := map[string]bool{}
	for i := range m.sections {
		m.sectionCursor, m.fieldCursor, m.focus = i, 0, paneOutline
		check("outline " + m.sections[i].Title)
		m, _ = press(t, m, "enter")
		for range m.sections[i].Fields {
			check("form " + m.sections[i].Title)
			m, _ = press(t, m, "down")
		}
		seen[m.sections[i].Title] = true
	}
	for _, title := range []string{"External sources (3)", "Source screening", "External checks (3)", "Check daily-allowance"} {
		if !seen[title] {
			t.Errorf("section %q never shown", title)
		}
	}
	m = selectField(t, m, "/external_checks/1/require/2")
	m, _ = press(t, m, "enter")
	if m.prompt.kind != promptEdit {
		t.Fatalf("enter on a rule: prompt %v", m.prompt.kind)
	}
	check("rule editor")
}

// TestEditARuleAsJSON: a rule is edited as one JSON value; input that is not
// JSON is refused as it is typed, and a rule the decoder refuses is set and
// shows its error on the rule.
func TestEditARuleAsJSON(t *testing.T) {
	m, _ := editModel(t, externalFixture)
	m = selectField(t, m, "/external_checks/1/require/1")
	m, _ = press(t, m, "enter")
	if m.prompt.kind != promptEdit || m.prompt.input.Value() != `{"pointer": "/risk/score", "op": "le", "number": "30"}` {
		t.Fatalf("rule editor: kind %v, input %q", m.prompt.kind, m.prompt.input.Value())
	}
	if !strings.Contains(view(m), "a JSON value") {
		t.Fatalf("the rule editor does not say what it takes:\n%s", view(m))
	}
	m = typeText(t, clearInput(t, m), `{"pointer": "/risk/score", "op": "le", "number": `)
	if !strings.Contains(view(m), "not a JSON value") {
		t.Fatalf("no live error for broken JSON:\n%s", view(m))
	}
	m, _ = press(t, m, "enter")
	if m.prompt.kind == promptNone {
		t.Fatal("broken JSON was set")
	}
	m = typeText(t, clearInput(t, m), `{"pointer": "/risk/score", "op": "lte", "number": "40"}`)
	m, _ = press(t, m, "enter")
	if got := m.session().Current().Draft.At("/external_checks/1/require/1/number").Text(); got != "40" {
		t.Fatalf("rule number = %q, want 40", got)
	}
	m = selectField(t, m, "/external_checks/1/require/1")
	m.focus = paneForm
	if out := view(m); !strings.Contains(out, "must be one of eq") || !strings.Contains(out, "does not pass check") {
		t.Fatalf("the rule's error is not shown on it:\n%s", out)
	}
}

// TestTryWithExternalChecks: a permit under a document with external checks
// names the checks that then decide.
func TestTryWithExternalChecks(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"cosigner.json": fixture(t, externalFixture)})
	m := New(ws, nil, nil)
	m, _ = press(t, m, "t")
	m, _ = press(t, m, "up")
	m = ctrl(t, m, tea.KeyCtrlU)
	m, _ = press(t, m, "mainnet", "down", treasuryAddr, "down", opsMainnet, "down", "5", "enter")
	if m.try.result == nil || m.try.result.ExternalChecks == nil {
		t.Fatalf("try: %+v err %q", m.try.result, m.try.err)
	}
	out := strings.Join(strings.Fields(view(m)), " ")
	if want := "permits the supplied transaction; then external checks ops-switch, screen-destination and daily-allowance decide"; !strings.Contains(out, want) {
		t.Fatalf("try view lacks %q:\n%s", want, view(m))
	}
	if strings.Contains(out, "cannot keep") {
		t.Fatalf("try view says a token cannot be kept:\n%s", view(m))
	}
}
