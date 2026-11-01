// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// Editing. A field is edited in a bar below the panes: a choice cycles
// through the values the role allows, anything else is typed. Every edit
// goes through the open file's session, which re-checks the document at once
// and keeps it for undo.

// prompt is the active edit bar: a field edit, an add, or a removal to
// confirm.
type prompt struct {
	kind promptKind
	// title names what is being done; hint shows under the input.
	title, hint string
	err         string
	input       textinput.Model

	field    policyauthor.Field
	choices  []string
	choice   int
	decimals uint64
	known    bool

	adds    []policyauthor.AddAction
	pick    int
	picking bool

	// suggestions are offered on tab for a term field; suggestion is the one
	// inserted last (-1 for none) and suggestBase the text before it.
	suggestions []string
	suggestion  int
	suggestBase string

	removal policyauthor.Removal
}

type promptKind int

const (
	promptNone promptKind = iota
	promptEdit
	promptChoice
	promptAdd
	promptRemove
)

// session returns the open file's edit session, starting one the first time.
// A file that is not JSON has none.
func (m Model) session() *policyauthor.Session {
	path := m.ws.Files[m.current].Path
	if s, ok := m.sessions[path]; ok {
		return s
	}
	s, err := policyauthor.NewSession(m.ws.Files[m.current])
	if err != nil {
		return nil
	}
	m.sessions[path] = s
	return s
}

// shown is the document the screen shows: the session's edited document,
// or the file as loaded when it cannot be edited.
func (m Model) shown() *policyauthor.File {
	if s := m.session(); s != nil {
		return s.Current()
	}
	return m.ws.Files[m.current]
}

// relayout rebuilds the outline after an edit, keeping the cursors in range.
func (m Model) relayout() Model {
	f := m.shown()
	m.sections = policyauthor.Outline(f, m.problemsFor(m.current, f), m.lookup)
	m.sectionCursor = max(0, min(m.sectionCursor, len(m.sections)-1))
	m.fieldCursor = max(0, min(m.fieldCursor, len(m.sections[m.sectionCursor].Fields)-1))
	return m
}

func (m Model) newInput(value string) textinput.Model {
	in := textinput.New()
	in.Prompt = "> "
	in.SetValue(value)
	in.CursorEnd()
	in.Width = max(10, m.width-4)
	in.Focus()
	return in
}

func (m Model) readOnly() (Model, bool) {
	if m.session() == nil {
		m.status = "This file is not valid JSON and cannot be edited here; repair it in a text editor and press r"
		return m, true
	}
	return m, false
}

// editField opens the editor for the selected field, or shows it in full
// when it cannot be edited.
func (m Model) editField() Model {
	s := m.sections[m.sectionCursor]
	if m.fieldCursor >= len(s.Fields) {
		return m
	}
	f := s.Fields[m.fieldCursor]
	if f.Edit == nil {
		return m.openField()
	}
	if next, ro := m.readOnly(); ro {
		return next
	}
	cur := m.session().Current().Draft.At(f.Edit.Pointer)
	p := prompt{field: f, title: "Edit " + f.Label}
	switch f.Edit.Kind {
	case policyauthor.EditChoice, policyauthor.EditBool:
		p.kind, p.choices = promptChoice, f.Edit.Choices
		if f.Edit.Kind == policyauthor.EditBool {
			p.choices = []string{"yes", "no"}
		}
		current := f.Edit.Input(cur, 0, false)
		for i, c := range p.choices {
			if c == current || (c == "yes" && current == "true") || (c == "no" && current == "false") {
				p.choice = i
			}
		}
		p.hint = "left/right: choose · enter: set · esc: cancel"
	default:
		p.kind = promptEdit
		p.decimals, _, p.known = f.Edit.Decimals(m.lookup)
		p.input = m.newInput(f.Edit.Input(cur, p.decimals, p.known))
		p.hint = editHint(*f.Edit, p.decimals, p.known, m.lookup)
		p.suggestion = -1
		if f.Edit.Kind == policyauthor.EditTerms || f.Edit.Kind == policyauthor.EditTerm {
			p.suggestions = f.Edit.Suggestions(m.session().Current().Draft)
			if len(p.suggestions) > 0 {
				p.hint = "tab: " + strings.Join(p.suggestions, ", ") + " · " + p.hint
			}
		}
	}
	m.prompt = p
	return m
}

// editHint says what a typed field takes; for an amount it names the
// decimals fixed for this edit and where they came from.
func editHint(e policyauthor.EditSpec, decimals uint64, known bool, lookup policyauthor.AssetLookup) string {
	switch e.Kind {
	case policyauthor.EditAmount:
		if !known {
			return "whole base units: this asset's decimals are unknown · enter: set · esc: cancel"
		}
		_, source, _ := e.Decimals(lookup)
		return fmt.Sprintf("display units, %d decimals (%s); stored in base units · enter: set · esc: cancel", decimals, source)
	case policyauthor.EditTerms:
		return "comma-separated " + termHint(e.Term) + " · enter: set · esc: cancel"
	case policyauthor.EditTerm:
		return termHint(e.Term) + " · enter: set · esc: cancel"
	}
	return "enter: set · esc: cancel"
}

func termHint(t policyauthor.TermKind) string {
	switch t {
	case policyauthor.TermAddress:
		return "addresses"
	case policyauthor.TermSource:
		return `addresses, "*" or @sets`
	case policyauthor.TermDestination:
		return `addresses, "*", "self" or @sets`
	case policyauthor.TermAsset:
		return `"algo", asa:<id>, "*" or @sets`
	case policyauthor.TermAssetRef:
		return `"algo" or asa:<id>`
	case policyauthor.TermNetwork:
		return `network tokens, or "*" for every network`
	case policyauthor.TermRekeyTarget:
		return "addresses or @sets"
	}
	return "values"
}

// toggle flips a yes/no field in place.
func (m Model) toggle() Model {
	s := m.sections[m.sectionCursor]
	if m.fieldCursor >= len(s.Fields) {
		return m
	}
	f := s.Fields[m.fieldCursor]
	if f.Edit == nil || f.Edit.Kind != policyauthor.EditBool {
		return m
	}
	if next, ro := m.readOnly(); ro {
		return next
	}
	value := "true"
	if node := m.session().Current().Draft.At(f.Edit.Pointer); node.Kind() == "boolean" && node.Bool() {
		value = "false"
	}
	return m.apply("Set "+f.Label, func(d *policy.Draft) (*policy.Draft, error) { return d.Set(f.Edit.Pointer, []byte(value)) })
}

// apply makes an edit through the session and lays the result out again.
func (m Model) apply(what string, edit func(*policy.Draft) (*policy.Draft, error)) Model {
	if err := m.session().Apply(edit); err != nil {
		m.status = what + " failed: " + err.Error()
		return m
	}
	m.status = what
	return m.relayout()
}

func (m Model) promptKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := &m.prompt
	if msg.String() == "esc" {
		m.prompt = prompt{}
		return m, nil
	}
	switch p.kind {
	case promptChoice:
		switch msg.String() {
		case "left", "h", "up", "k", "shift+tab":
			p.choice = (p.choice + len(p.choices) - 1) % len(p.choices)
		case "right", "l", "down", "j", "tab", " ":
			p.choice = (p.choice + 1) % len(p.choices)
		case "enter":
			return m.commitEdit(p.choices[p.choice]), nil
		}
		return m, nil
	case promptRemove:
		switch msg.String() {
		case "y":
			r := p.removal
			m.prompt = prompt{}
			return m.apply(strings.ToUpper(r.Label[:1])+r.Label[1:], r.Apply), nil
		case "n":
			m.prompt = prompt{}
		}
		return m, nil
	case promptAdd:
		if p.picking {
			switch msg.String() {
			case "up", "k":
				p.pick = max(0, p.pick-1)
			case "down", "j":
				p.pick = min(len(p.adds)-1, p.pick+1)
			case "enter":
				if !p.adds[p.pick].NeedsInput() {
					return m.applyAdd(p.adds[p.pick], ""), nil
				}
				p.picking = false
				p.title, p.hint = p.adds[p.pick].Label, p.adds[p.pick].Prompt+" · enter: add · esc: cancel"
				p.input = m.newInput("")
			}
			return m, nil
		}
		if msg.String() == "enter" {
			return m.applyAdd(p.adds[p.pick], p.input.Value()), nil
		}
	case promptEdit:
		switch msg.String() {
		case "enter":
			return m.commitEdit(p.input.Value()), nil
		case "tab":
			if len(p.suggestions) > 0 {
				m.prompt = p.suggest(p.field.Edit.Kind == policyauthor.EditTerms)
				return m, nil
			}
		}
		p.suggestion = -1
	}
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(msg)
	p.err = ""
	if p.kind == promptEdit {
		if _, err := p.field.Edit.Value(p.input.Value(), p.decimals, p.known); err != nil {
			p.err = err.Error()
		}
	}
	return m, cmd
}

// suggest inserts the next suggestion: after the typed terms for a list, in
// place of the value for one term. A repeated tab replaces the suggestion it
// inserted with the next one.
func (p prompt) suggest(list bool) prompt {
	if p.suggestion < 0 {
		p.suggestBase = strings.TrimRight(strings.TrimSpace(p.input.Value()), ",")
		p.suggestion = 0
	} else {
		p.suggestion = (p.suggestion + 1) % len(p.suggestions)
	}
	value := p.suggestions[p.suggestion]
	if list && p.suggestBase != "" {
		value = p.suggestBase + ", " + value
	}
	p.input.SetValue(value)
	p.input.CursorEnd()
	p.err = ""
	if _, err := p.field.Edit.Value(value, p.decimals, p.known); err != nil {
		p.err = err.Error()
	}
	return p
}

// commitEdit writes input to the field. An amount's decimals must still be
// those the edit started with: if the asset's metadata changed meanwhile, the
// value is not written and the editor shows both.
func (m Model) commitEdit(input string) Model {
	p := &m.prompt
	f := p.field
	if p.kind == promptEdit && f.Edit.Kind == policyauthor.EditAmount {
		if now, _, known := f.Edit.Decimals(m.lookup); known != p.known || now != p.decimals {
			p.err = fmt.Sprintf("the asset's decimals changed from %d to %d while editing; check the amount and enter it again", p.decimals, now)
			p.decimals, p.known = now, known
			return m
		}
	}
	value, err := f.Edit.Value(input, p.decimals, p.known)
	if err != nil {
		p.err = err.Error()
		return m
	}
	m.prompt = prompt{}
	return m.apply("Set "+f.Label, func(d *policy.Draft) (*policy.Draft, error) { return d.Set(f.Edit.Pointer, value) })
}

// startAdd offers the selected section's add actions.
func (m Model) startAdd() Model {
	if next, ro := m.readOnly(); ro {
		return next
	}
	adds := m.sections[m.sectionCursor].Adds
	if len(adds) == 0 {
		m.status = "Nothing can be added to " + m.sections[m.sectionCursor].Title
		return m
	}
	p := prompt{kind: promptAdd, adds: adds, title: "Add to " + m.sections[m.sectionCursor].Title, hint: "up/down: choose · enter: select · esc: cancel", picking: true}
	if len(adds) == 1 {
		if !adds[0].NeedsInput() {
			return m.applyAdd(adds[0], "")
		}
		p.picking = false
		p.title, p.hint = adds[0].Label, adds[0].Prompt+" · enter: add · esc: cancel"
		p.input = m.newInput("")
	}
	m.prompt = p
	return m
}

// applyAdd runs an add action and lays the result out again.
func (m Model) applyAdd(a policyauthor.AddAction, input string) Model {
	if err := m.session().Apply(func(d *policy.Draft) (*policy.Draft, error) { return a.Apply(d, input) }); err != nil {
		m.prompt.err = err.Error()
		if m.prompt.kind == promptNone {
			m.status = a.Label + " failed: " + err.Error()
		}
		return m
	}
	m.prompt = prompt{}
	m.status = a.Label
	return m.relayout()
}

// startCopy copies the selected field (a list member or a rekey edge), or
// the selected section from the outline (a route).
func (m Model) startCopy() Model {
	if next, ro := m.readOnly(); ro {
		return next
	}
	s := m.sections[m.sectionCursor]
	var a *policyauthor.AddAction
	if m.focus == paneForm && m.fieldCursor < len(s.Fields) {
		a = s.Fields[m.fieldCursor].Copy
	} else if m.focus == paneOutline {
		a = s.Copy
	}
	if a == nil {
		m.status = "Nothing to copy here; sets are copied with a in their section"
		return m
	}
	if !a.NeedsInput() {
		return m.applyAdd(*a, "")
	}
	m.prompt = prompt{kind: promptAdd, adds: []policyauthor.AddAction{*a}, title: a.Label, hint: a.Prompt + " · enter: copy · esc: cancel", input: m.newInput("")}
	return m
}

// startRemove asks to confirm removing the selected field, or the selected
// section from the outline.
func (m Model) startRemove() Model {
	if next, ro := m.readOnly(); ro {
		return next
	}
	s := m.sections[m.sectionCursor]
	var r *policyauthor.Removal
	if m.focus == paneForm && m.fieldCursor < len(s.Fields) {
		r = s.Fields[m.fieldCursor].Remove
	} else if m.focus == paneOutline {
		r = s.Remove
	}
	if r == nil {
		m.status = "Nothing to remove here"
		return m
	}
	m.prompt = prompt{kind: promptRemove, removal: *r, title: strings.ToUpper(r.Label[:1]) + r.Label[1:] + "?", hint: "y: remove · n/esc: keep"}
	return m
}

func (m Model) undo() Model {
	if s := m.session(); s != nil && s.Undo() {
		m.status = "Undone"
		return m.relayout()
	}
	m.status = "Nothing to undo"
	return m
}

func (m Model) redo() Model {
	if s := m.session(); s != nil && s.Redo() {
		m.status = "Redone"
		return m.relayout()
	}
	m.status = "Nothing to redo"
	return m
}

// promptLines renders the edit bar.
func (m Model) promptLines() []string {
	p := m.prompt
	lines := []string{m.styles.title.Render(ansi.Truncate(p.title, m.width, "…"))}
	switch p.kind {
	case promptChoice:
		var parts []string
		for i, c := range p.choices {
			if i == p.choice {
				parts = append(parts, m.styles.selected.Render(" "+c+" "))
			} else {
				parts = append(parts, " "+c+" ")
			}
		}
		lines = append(lines, ansi.Truncate(strings.Join(parts, " "), m.width, "…"))
	case promptAdd:
		if p.picking {
			for i, a := range p.adds {
				line := "  " + a.Label
				if i == p.pick {
					line = m.styles.selected.Render("> " + a.Label)
				}
				lines = append(lines, ansi.Truncate(line, m.width, "…"))
			}
		} else {
			lines = append(lines, ansi.Truncate(p.input.View(), m.width, "…"))
		}
	case promptEdit:
		lines = append(lines, ansi.Truncate(p.input.View(), m.width, "…"))
	}
	if p.err != "" {
		lines = append(lines, m.styles.err.Render(ansi.Truncate(p.err, m.width, "…")))
	}
	lines = append(lines, m.styles.subtle.Render(ansi.Truncate(p.hint, m.width, "…")))
	return lines
}
