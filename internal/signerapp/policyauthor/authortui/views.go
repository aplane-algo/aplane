// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// The views reached from a document: its problems, its explanation, a
// comparison with another file, and help. Each is a scrollable page; esc
// returns to the document.

// location is where a problem shows in the document: a section, and a field
// in it or -1 for the section itself.
type location struct {
	section, field int
	problem        policyauthor.Problem
}

// problemLocations lists every problem in outline order.
func (m Model) problemLocations() []location {
	var out []location
	for si, s := range m.sections {
		for _, p := range s.Problems {
			out = append(out, location{section: si, field: -1, problem: p})
		}
		for fi, f := range s.Fields {
			for _, p := range f.Problems {
				out = append(out, location{section: si, field: fi, problem: p})
			}
		}
	}
	return out
}

// goTo puts the cursor on a location.
func (m Model) goTo(l location) Model {
	m.screen = screenDocument
	m.sectionCursor = l.section
	if l.field >= 0 {
		m.fieldCursor, m.focus = l.field, paneForm
	} else {
		m.fieldCursor, m.focus = 0, paneOutline
	}
	return m
}

// jump moves to the next (dir 1) or previous (dir -1) problem after the
// cursor, wrapping around.
func (m Model) jump(dir int) Model {
	locs := m.problemLocations()
	if len(locs) == 0 {
		m.status = "No problems in this file"
		return m
	}
	cur := location{section: m.sectionCursor, field: -1}
	if m.focus == paneForm {
		cur.field = m.fieldCursor
	}
	before := func(a, b location) bool {
		return a.section < b.section || (a.section == b.section && a.field < b.field)
	}
	if dir > 0 {
		for _, l := range locs {
			if before(cur, l) {
				return m.goTo(l)
			}
		}
		return m.goTo(locs[0])
	}
	for i := len(locs) - 1; i >= 0; i-- {
		if before(locs[i], cur) {
			return m.goTo(locs[i])
		}
	}
	return m.goTo(locs[len(locs)-1])
}

// page is a scrollable text view.
type page struct {
	title  string
	lines  []string
	offset int
}

func (m Model) pageHeight() int { return max(3, m.height-4) }

func (m Model) openPage(s screen, title string, lines []string) Model {
	m.screen = s
	m.page = page{title: title, lines: lines}
	return m
}

func (m Model) pageKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	h := m.pageHeight()
	maxOffset := max(0, len(m.page.lines)-h)
	switch msg.String() {
	case "esc":
		m.screen = screenDocument
		return m, nil
	case "q":
		return m.quit()
	case "up", "k":
		m.page.offset--
	case "down", "j":
		m.page.offset++
	case "pgup":
		m.page.offset -= h
	case "pgdown", " ":
		m.page.offset += h
	case "home", "g":
		m.page.offset = 0
	case "end", "G":
		m.page.offset = maxOffset
	case "o":
		if m.screen == screenCompare {
			return m.openComparePick(), nil
		}
	}
	m.page.offset = max(0, min(m.page.offset, maxOffset))
	return m, nil
}

func (m Model) pageView() string {
	h := m.pageHeight()
	end := min(len(m.page.lines), m.page.offset+h)
	var b strings.Builder
	b.WriteString(m.styles.title.Render(ansi.Truncate(m.page.title, m.width, "…")) + "\n\n")
	for _, line := range m.page.lines[m.page.offset:end] {
		b.WriteString(ansi.Truncate(line, m.width, "…") + "\n")
	}
	if end < len(m.page.lines) {
		b.WriteString(m.styles.subtle.Render(fmt.Sprintf("… %d more line(s)", len(m.page.lines)-end)) + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// Problems list.

func (m Model) openProblems() Model {
	m.screen = screenProblems
	m.problemCursor = 0
	return m
}

func (m Model) problemsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	locs := m.problemLocations()
	switch msg.String() {
	case "esc":
		m.screen = screenDocument
		return m, nil
	case "q":
		return m.quit()
	}
	if len(locs) == 0 {
		return m, nil
	}
	switch msg.String() {
	case "up", "k":
		m.problemCursor--
	case "down", "j":
		m.problemCursor++
	case "enter":
		if m.problemCursor >= 0 && m.problemCursor < len(locs) {
			return m.goTo(locs[m.problemCursor]), nil
		}
	}
	m.problemCursor = max(0, min(len(locs)-1, m.problemCursor))
	return m, nil
}

func (m Model) problemsView() string {
	locs := m.problemLocations()
	var b strings.Builder
	b.WriteString(m.styles.title.Render("Problems in "+filepath.Base(m.file().Path)) + "\n\n")
	if len(locs) == 0 {
		b.WriteString("No problems.\n")
	}
	var lines []string
	for i, l := range locs {
		where := m.sections[l.section].Title
		if l.field >= 0 {
			where += " › " + m.sections[l.section].Fields[l.field].Label
		}
		mark := "⚠"
		if l.problem.Severity == policyauthor.SeverityError {
			mark = "✗"
		}
		text := fmt.Sprintf("%s %s: %s", mark, where, l.problem.Message)
		if l.problem.Pointer != "" {
			text += "  (" + l.problem.Pointer + ")"
		}
		text = ansi.Truncate(text, m.width-2, "…")
		if i == m.problemCursor {
			text = m.styles.selected.Render("> " + text)
		} else {
			text = "  " + text
		}
		lines = append(lines, text)
	}
	b.WriteString(strings.Join(window(lines, m.problemCursor, m.pageHeight()), "\n"))
	return strings.TrimSuffix(b.String(), "\n")
}

// Explain.

func (m Model) openExplain() Model {
	f := m.shown()
	if f.Document == nil {
		m.status = "Explain needs a valid document; this one is " + f.State.String()
		return m
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(policyauthor.Explain(f.Document, m.lookup), "\n"), "\n") {
		lines = append(lines, wrap(line, max(20, m.width-2))...)
	}
	return m.openPage(screenExplain, "Explain "+filepath.Base(f.Path), lines)
}

// Compare.

// openCompare compares a key document with the workspace default. A default
// document, or a workspace without one, picks the file to compare with.
func (m Model) openCompare() Model {
	f := m.file()
	if def := m.ws.Default(); def != nil && def != f {
		return m.compareWith(def)
	}
	return m.openComparePick()
}

func (m Model) openComparePick() Model {
	if len(m.ws.Files) < 2 {
		m.screen = screenDocument
		m.status = "Nothing to compare with: the workspace holds one file"
		return m
	}
	m.screen = screenComparePick
	m.pickCursor = 0
	if m.pickCursor == m.current {
		m.pickCursor = 1
	}
	return m
}

func (m Model) comparePickKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.screen = screenDocument
	case "q":
		return m.quit()
	case "up", "k":
		for i := m.pickCursor - 1; i >= 0; i-- {
			if i != m.current {
				m.pickCursor = i
				break
			}
		}
	case "down", "j":
		for i := m.pickCursor + 1; i < len(m.ws.Files); i++ {
			if i != m.current {
				m.pickCursor = i
				break
			}
		}
	case "enter":
		return m.compareWith(m.ws.Files[m.pickCursor]), nil
	}
	return m, nil
}

func (m Model) comparePickView() string {
	var b strings.Builder
	b.WriteString(m.styles.title.Render("Compare "+filepath.Base(m.file().Path)+" with") + "\n\n")
	var lines []string
	selected := 0
	for i, f := range m.ws.Files {
		if i == m.current {
			continue
		}
		key := f.Key
		if key == "" {
			key = "(no key)"
		}
		line := ansi.Truncate(fmt.Sprintf("%-28s %-10s %s", filepath.Base(f.Path), f.State, key), m.width-2, "…")
		if i == m.pickCursor {
			selected = len(lines)
			line = m.styles.selected.Render("> " + line)
		} else {
			line = "  " + line
		}
		lines = append(lines, line)
	}
	b.WriteString(strings.Join(window(lines, selected, m.listHeight()), "\n"))
	return b.String()
}

// compareWith shows how the open file differs from base.
func (m Model) compareWith(base *policyauthor.File) Model {
	f := m.shown()
	c := policyauthor.Compare(base, f)
	label := filepath.Base(base.Path)
	if base == m.ws.Default() {
		label = "the workspace default (" + label + ")"
	}
	var lines []string
	for _, line := range wrap(fmt.Sprintf("%s compared with %s, by %s", filepath.Base(f.Path), label, c.Mode), max(20, m.width-2)) {
		lines = append(lines, m.styles.subtle.Render(line))
	}
	if c.Note != "" {
		for _, line := range wrap(c.Note, max(20, m.width-2)) {
			lines = append(lines, m.styles.subtle.Render(line))
		}
	}
	lines = append(lines, "")
	if c.Identical {
		lines = append(lines, "No differences.")
	}
	if !c.Identical && len(c.Changes) == 0 && c.Note == "" {
		lines = append(lines, "No differences in effect.")
	}
	for _, ch := range c.Changes {
		effect := fmt.Sprintf("%-9s", ch.Effect)
		switch ch.Effect {
		case "loosened", "removed":
			effect = m.styles.warn.Render(effect)
		case "tightened":
			effect = m.styles.label.Render(effect)
		}
		for i, line := range wrap(ch.Path+": "+ch.Summary, max(20, m.width-12)) {
			if i == 0 {
				lines = append(lines, effect+"  "+line)
			} else {
				lines = append(lines, strings.Repeat(" ", 11)+line)
			}
		}
	}
	return m.openPage(screenCompare, "Compare", lines)
}

// Field detail.

// openField shows the selected field in full: its value wrapped to the
// window, its note, its pointer and its problems, for values longer than the
// form can show.
func (m Model) openField() Model {
	s := m.sections[m.sectionCursor]
	if m.fieldCursor >= len(s.Fields) {
		return m
	}
	f := s.Fields[m.fieldCursor]
	width := max(20, m.width-2)
	var lines []string
	if f.Pointer != "" {
		lines = append(lines, m.styles.subtle.Render(ansi.Truncate(f.Pointer, width, "…")), "")
	}
	lines = append(lines, wrap(f.Value, width)...)
	if f.Note != "" {
		lines = append(lines, "")
		for _, line := range wrap(f.Note, width) {
			lines = append(lines, m.styles.subtle.Render(line))
		}
	}
	if len(f.Problems) > 0 {
		lines = append(lines, "")
		for _, p := range f.Problems {
			lines = append(lines, m.problemLines(p, width)...)
		}
	}
	return m.openPage(screenField, s.Title+" › "+f.Label, lines)
}

// Help.

func (m Model) openHelp() Model {
	return m.openPage(screenHelp, "appolicy keys", []string{
		"Files",
		"  up/down    select a file",
		"  enter      open it",
		"  r          reload the workspace from disk",
		"  q          quit",
		"",
		"Document",
		"  up/down    move in the focused pane",
		"  tab        switch between the outline and the form",
		"  left/right outline / form; enter opens a section's form",
		"  enter      in the form: edit the selected field",
		"  space      toggle a yes/no field",
		"  v          show the selected field in full",
		"  a          add to the selected section (a route, a set, a limit...)",
		"  d          remove the selected field, or a route from the outline",
		"  u ctrl+r   undo / redo",
		"  s          save: review the changes, then y to write",
		"  ] [        next / previous problem",
		"  p          list every problem; enter jumps to it",
		"  x          explain the document in plain language",
		"  c          compare with the workspace default, or with a file you pick",
		"  r          reload from disk",
		"  esc        back; q quit",
		"",
		"Pages (problems, explain, compare, help)",
		"  up/down pgup/pgdown home/end   scroll",
		"  o          in compare: pick another file",
		"  esc        back to the document",
		"",
		"appolicy reads files only. It never contacts a node: review and install a",
		"policy with apadmin policy diff and apadmin policy apply.",
	})
}
