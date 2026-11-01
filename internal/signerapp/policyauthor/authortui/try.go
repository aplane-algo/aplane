// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Trying a transaction: t opens a form on the open document, as edited;
// enter asks what it decides and ctrl+s keeps the answer as a saved case.
// The saved cases run again after every key, against the documents as
// edited, and T lists them.

const (
	tryNetwork = iota
	tryFrom
	tryTo
	tryAmount
	tryAsset
	tryFee
	tryCloseTo
	tryClawbackFrom
	tryRekeyTo
	tryRekeyHeld
	tryFieldCount
)

var tryLabels = [tryFieldCount]string{
	"Network", "From", "To (or self)", "Amount (base units)", "Asset ID (blank: ALGO)", "Fee (microAlgos)",
	"Close to", "Clawback from", "Rekey to", "Node holds the rekey target",
}

// tryLabelWidth is the width of the form's label column.
const tryLabelWidth = 28

type tryForm struct {
	inputs [tryFieldCount]textinput.Model
	held   bool
	cursor int
	// file is the document tried, by index; result is the last answer and
	// txn what it was asked of.
	file   int
	result *policyauthor.TryResult
	txn    policyauthor.TryTxn
	err    string
	// naming is set while the case's name is entered; offset scrolls the
	// result.
	naming bool
	name   textinput.Model
	offset int
}

// edited drops the answer when the transaction changes, so a saved case is
// always the transaction that was tried.
func (t *tryForm) edited() {
	t.result, t.err, t.offset = nil, "", 0
}

func (m Model) startTry() Model {
	f := m.shown()
	var form tryForm
	defaults := [tryFieldCount]string{tryNetwork: "testnet", tryFee: "1000"}
	// A signer key's own document is about that address.
	if f.Role == noderole.RoleSigner && f.Key != "" && f.Key != "default" {
		defaults[tryFrom] = f.Key
	}
	for i := range form.inputs {
		if i == tryRekeyHeld {
			continue
		}
		in := m.newInput(defaults[i])
		in.Prompt = ""
		in.Width = max(10, m.width-tryLabelWidth-2)
		in.Blur()
		form.inputs[i] = in
	}
	form.file = m.current
	form.cursor = tryFrom
	form.inputs[tryFrom].Focus()
	m.try = form
	m.screen = screenTry
	return m
}

func (t *tryForm) focus(i int) {
	if t.cursor != tryRekeyHeld {
		t.inputs[t.cursor].Blur()
	}
	t.cursor = (i + tryFieldCount) % tryFieldCount
	if t.cursor != tryRekeyHeld {
		t.inputs[t.cursor].Focus()
	}
}

func (m Model) tryKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	t := &m.try
	if t.naming {
		switch msg.String() {
		case "esc":
			t.naming = false
			return m, nil
		case "enter":
			return m.saveCase(strings.TrimSpace(t.name.Value())), nil
		}
		var cmd tea.Cmd
		t.name, cmd = t.name.Update(msg)
		return m, cmd
	}
	switch msg.String() {
	case "esc":
		m.screen = screenDocument
		return m, nil
	case "up", "shift+tab":
		t.focus(t.cursor - 1)
		return m, nil
	case "down", "tab":
		t.focus(t.cursor + 1)
		return m, nil
	case "enter":
		return m.runTry(), nil
	case "ctrl+s":
		if t.result == nil {
			t.err = "Try the transaction first (enter), then keep its answer as a case"
			return m, nil
		}
		t.naming = true
		t.name = m.newInput("")
		return m, nil
	case "pgdown":
		h := max(1, m.tryResultHeight())
		t.offset = min(t.offset+h, max(0, len(m.tryResultLines())-h))
		return m, nil
	case "pgup":
		t.offset = max(0, t.offset-max(1, m.tryResultHeight()))
		return m, nil
	case " ":
		if t.cursor == tryRekeyHeld {
			t.held = !t.held
			t.edited()
			return m, nil
		}
	}
	if t.cursor == tryRekeyHeld {
		return m, nil
	}
	before := t.inputs[t.cursor].Value()
	var cmd tea.Cmd
	t.inputs[t.cursor], cmd = t.inputs[t.cursor].Update(msg)
	if t.inputs[t.cursor].Value() != before {
		t.edited()
	}
	return m, cmd
}

// tryTxn reads the form.
func (t tryForm) tryTxn() (policyauthor.TryTxn, error) {
	value := func(i int) string { return strings.TrimSpace(t.inputs[i].Value()) }
	number := func(i int) (uint64, error) {
		if value(i) == "" {
			return 0, nil
		}
		n, err := strconv.ParseUint(strings.ReplaceAll(value(i), "_", ""), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %q is not a whole number", tryLabels[i], value(i))
		}
		return n, nil
	}
	txn := policyauthor.TryTxn{
		Network:         value(tryNetwork),
		Sender:          value(tryFrom),
		Receiver:        value(tryTo),
		CloseTo:         value(tryCloseTo),
		ClawbackFrom:    value(tryClawbackFrom),
		RekeyTo:         value(tryRekeyTo),
		RekeyTargetHeld: t.held,
	}
	if txn.Receiver == "self" {
		txn.Receiver = txn.Sender
	}
	var err error
	if txn.Amount, err = number(tryAmount); err != nil {
		return txn, err
	}
	if txn.Asset, err = number(tryAsset); err != nil {
		return txn, err
	}
	if value(tryFee) == "" {
		txn.Fee = 1000
	} else if txn.Fee, err = number(tryFee); err != nil {
		return txn, err
	}
	return txn, nil
}

func (m Model) runTry() Model {
	t := &m.try
	t.edited()
	txn, err := t.tryTxn()
	if err != nil {
		t.err = err.Error()
		return m
	}
	result, err := policyauthor.Try(m.shownFile(t.file), txn, m.networks)
	if err != nil {
		t.err = err.Error()
		return m
	}
	t.result, t.txn = &result, txn
	return m
}

func (m Model) saveCase(name string) Model {
	t := &m.try
	if name == "" {
		t.err = "Enter a name for the case"
		return m
	}
	cases, err := policyauthor.LoadCases(m.ws.Dir())
	if errors.Is(err, os.ErrNotExist) {
		cases, err = &policyauthor.CaseFile{}, nil
	}
	if err != nil {
		t.err = err.Error()
		return m
	}
	c := policyauthor.Case{
		Name:     name,
		Document: m.caseDocument(t.file),
		Txn:      policyauthor.CaseTxnOf(t.txn),
		Expect:   policyauthor.ExpectOf(*t.result),
	}
	if err := cases.Add(c); err != nil {
		t.err = err.Error()
		return m
	}
	if err := cases.Save(m.ws.Dir()); err != nil {
		t.err = "Could not save the case: " + err.Error()
		return m
	}
	t.naming = false
	m.cases, m.casesErr = cases, ""
	m.status = fmt.Sprintf("Saved case %q to %s", name, policyauthor.CasesPath(m.ws.Dir()))
	return m
}

// caseDocument names file i as a case does: by its path in the workspace
// directory.
func (m Model) caseDocument(i int) string {
	name, err := relativeTo(m.ws.Dir(), m.ws.Files[i].Path)
	if err != nil {
		return m.ws.Files[i].Path
	}
	return name
}

// tryFormLines are the form's lines: its title, its fields, and the case
// name prompt while naming. They are always shown in full.
func (m Model) tryFormLines() []string {
	t := m.try
	f := m.shownFile(t.file)
	lines := []string{
		m.styles.title.Render("Try a transaction") + "  " + m.styles.subtle.Render(fmt.Sprintf("against %s (%s document %q, as edited)", m.caseDocument(t.file), f.Role, f.Key)),
		"",
	}
	for i := 0; i < tryFieldCount; i++ {
		label := fmt.Sprintf("%-*s", tryLabelWidth, tryLabels[i])
		value := ""
		if i == tryRekeyHeld {
			value = "no"
			if t.held {
				value = "yes"
			}
		} else {
			value = t.inputs[i].View()
		}
		if i == t.cursor {
			label = m.styles.selected.Render(label)
		} else {
			label = m.styles.label.Render(label)
		}
		lines = append(lines, label+" "+value)
	}
	if t.naming {
		lines = append(lines, "", "Name for the case:", t.name.View())
	}
	return append(lines, "")
}

// tryResultLines are the answer, or why there is none, wrapped to the
// terminal: every word of it matters.
func (m Model) tryResultLines() []string {
	t := m.try
	var lines []string
	add := func(style lipgloss.Style, indent, text string) {
		for _, l := range wrap(text, max(10, m.width-len(indent))) {
			lines = append(lines, indent+style.Render(l))
		}
	}
	if t.err != "" {
		add(m.styles.err, "", t.err)
	}
	if r := t.result; r != nil {
		add(m.styles.label, "", r.Summary)
		for _, v := range r.Violations {
			add(m.styles.err, "  ", "["+v.RuleID+"] "+v.Message)
		}
		lines = append(lines, m.styles.subtle.Render("assumed:"))
		for _, a := range r.Assumes {
			add(m.styles.subtle, "  - ", a)
		}
	}
	return lines
}

// tryResultHeight is the rows left for the answer below the form.
func (m Model) tryResultHeight() int {
	return m.height - 2 - len(m.tryFormLines())
}

// tryView shows the whole form and, below it, as much of the answer as fits,
// scrolled with pgup and pgdown. A terminal too short for the form shows the
// part around the focused field.
func (m Model) tryView() string {
	form := m.tryFormLines()
	result := m.tryResultLines()
	var lines []string
	if h := m.tryResultHeight(); h < 2 {
		focus := 2 + m.try.cursor
		if m.try.naming {
			focus = len(form) - 2
		}
		lines = window(append(form, result...), focus, max(3, m.height-2))
	} else {
		offset := max(0, min(m.try.offset, len(result)-h))
		end := min(len(result), offset+h)
		shown := result[offset:end]
		if end < len(result) {
			shown = append(shown[:len(shown)-1], m.styles.subtle.Render(fmt.Sprintf("… %d more line(s): pgdown", len(result)-end+1)))
		}
		lines = append(form, shown...)
	}
	for i, l := range lines {
		lines[i] = ansi.Truncate(l, m.width, "…")
	}
	return strings.Join(lines, "\n")
}

// Saved cases.

// loadCases reads the workspace's saved cases; none is not an error.
func (m Model) loadCases() Model {
	cases, err := policyauthor.LoadCases(m.ws.Dir())
	switch {
	case errors.Is(err, os.ErrNotExist):
		m.cases, m.casesErr = nil, ""
	case err != nil:
		m.cases, m.casesErr = nil, err.Error()
	default:
		m.cases, m.casesErr = cases, ""
	}
	return m
}

// caseResults runs the saved cases against the documents as edited.
func (m Model) caseResults() []policyauthor.CaseResult {
	if m.cases == nil {
		return nil
	}
	return policyauthor.RunCases(m.cases.Cases, m.ws.Documents(m.shownFile), m.networks)
}

// casesLabel is the header's summary of the saved cases, "" when there are
// none.
func (m Model) casesLabel() string {
	if m.casesErr != "" {
		return m.styles.err.Render("cases file unreadable")
	}
	results := m.caseResults()
	if len(results) == 0 {
		return ""
	}
	failing := 0
	for _, r := range results {
		if !r.Passed {
			failing++
		}
	}
	if failing > 0 {
		return m.styles.err.Render(fmt.Sprintf("cases: %d of %d failing (T)", failing, len(results)))
	}
	return m.styles.subtle.Render(fmt.Sprintf("cases: %d pass (T)", len(results)))
}

func (m Model) openCases() Model {
	dir := m.ws.Dir()
	path := policyauthor.CasesPath(dir)
	var lines []string
	switch {
	case m.casesErr != "":
		lines = append(lines, m.styles.err.Render(m.casesErr))
	case m.cases == nil || len(m.cases.Cases) == 0:
		lines = append(lines, "No saved cases. Try a transaction with t, then keep its answer with ctrl+s.", "They are saved to "+path+".")
	default:
		lines = append(lines, m.styles.subtle.Render(fmt.Sprintf("%s, run against the documents as edited (%s)", path, m.networks.Source)), "")
		for _, r := range m.caseResults() {
			switch {
			case r.Err != nil:
				lines = append(lines, m.styles.err.Render("ERROR ")+r.Case.Name, "      "+r.Err.Error())
			case r.Passed:
				lines = append(lines, m.styles.subtle.Render("ok    ")+r.Case.Name)
			default:
				lines = append(lines, m.styles.err.Render("FAIL  ")+r.Case.Name,
					fmt.Sprintf("      got %s, want %s", expectLabel(policyauthor.ExpectOf(r.Got)), expectLabel(r.Case.Expect)))
			}
		}
	}
	return m.openPage(screenCases, "Saved cases", lines)
}

func expectLabel(e policyauthor.CaseExpect) string {
	if e.RuleID == "" {
		return e.Outcome
	}
	return fmt.Sprintf("%s (rule %s)", e.Outcome, e.RuleID)
}

// relativeTo is path relative to dir, both made absolute first.
func relativeTo(dir, path string) (string, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Rel(absDir, absPath)
}
