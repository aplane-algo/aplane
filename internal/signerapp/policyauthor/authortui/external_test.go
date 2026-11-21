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

// TestTryAnswersInTheForm: on a document with external checks the try form
// ends with the answers to judge them on; the result shows the lookups and
// what each answer decided, and a kept case keeps the answers. A document
// without checks has no such field.
func TestTryAnswersInTheForm(t *testing.T) {
	signer, _ := workspace(t, map[string][]byte{"treasury.json": fixture(t, "signer_key_full.json")})
	m, _ := press(t, New(signer, nil, nil), "t")
	if m.try.count != tryAnswers || strings.Contains(view(m), tryLabels[tryAnswers]) {
		t.Fatalf("a signer document's form shows the answers field:\n%s", view(m))
	}

	ws, dir := workspace(t, map[string][]byte{"cosigner.json": fixture(t, externalFixture)})
	ops := filepath.Join(dir, "ops.answer")
	fail := filepath.Join(dir, "fail.answer")
	for path, body := range map[string]string{ops: `{"enabled": true}`, fail: `{"sanctioned": true, "risk": {"score": 1, "level": "low"}}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m = New(ws, nil, nil)
	m, _ = press(t, m, "t")
	if !strings.Contains(view(m), tryLabels[tryAnswers]) {
		t.Fatalf("the form lacks the answers field:\n%s", view(m))
	}
	m, _ = press(t, m, "up")
	m = ctrl(t, m, tea.KeyCtrlU)
	m, _ = press(t, m, "mainnet", "down", treasuryAddr, "down", opsMainnet, "down", "5")
	for m.try.cursor != tryAnswers {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "ops-switch="+ops, " ", "screen-destination="+fail, "enter")
	if m.try.err != "" || m.try.result == nil || m.try.result.OutcomeWord() != "reject" {
		t.Fatalf("try: err %q, result %+v", m.try.err, m.try.result)
	}
	// Wrapping may break a line at a space or after a hyphen, so the lines
	// are compared without their spaces.
	squeeze := func(s string) string { return strings.Join(strings.Fields(s), "") }
	out := squeeze(ansi.Strip(strings.Join(m.tryResultLines(), "\n")))
	for _, want := range []string{
		"but external check screen-destination refuses it",
		"lookups the cosigner would make:",
		"ops-switch, the request: passes",
		"refuses (external_check:screen-destination): /sanctioned = true, want eq false",
		"still to decide, with no answer given:",
	} {
		if !strings.Contains(out, squeeze(want)) {
			t.Fatalf("try result lacks %q:\n%s", want, strings.Join(m.tryResultLines(), "\n"))
		}
	}
	m = ctrl(t, m, tea.KeyCtrlS)
	m, _ = press(t, m, "sanctioned", "enter")
	cases, err := policyauthor.LoadCases(dir)
	if err != nil || len(cases.Cases) != 1 {
		t.Fatalf("saved = %+v, %v", cases, err)
	}
	c := cases.Cases[0]
	if squeeze(string(c.Answers["ops-switch"].Answer)) != `{"enabled":true}` || len(c.Answers) != 2 ||
		c.Expect != (policyauthor.CaseExpect{Outcome: "reject", RuleID: "external_check:screen-destination"}) {
		t.Fatalf("case = %+v", c)
	}
	if !strings.Contains(m.casesLabel(), "cases: 1 pass") {
		t.Fatalf("the kept case does not pass again: %q", m.casesLabel())
	}

	// An answer that cannot apply is reported, not tried.
	m, _ = press(t, m, " ", "nope="+ops, "enter")
	if m.try.result != nil || !strings.Contains(m.try.err, "no external check nope") {
		t.Fatalf("bad answer: err %q", m.try.err)
	}
}
