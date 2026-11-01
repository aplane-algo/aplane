// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package authortui is appolicy's terminal user interface: it presents a
// policyauthor workspace for reading and navigating. All policy logic lives in
// policyauthor; this package only lays out what the core returns and turns
// keys into moves.
package authortui

import (
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	screenFiles screen = iota
	screenDocument
	screenProblems
	screenExplain
	screenCompare
	screenComparePick
	screenHelp
	screenField
)

type pane int

const (
	paneOutline pane = iota
	paneForm
)

// Model is the appolicy TUI. It is a bubbletea value model.
type Model struct {
	ws     *policyauthor.Workspace
	lookup policyauthor.AssetLookup
	// diagnostics are messages about data sources (such as an unusable ASA
	// cache) reported while laying out documents; the first is shown in the
	// status line.
	diagnostics *[]string
	styles      styles

	width, height int
	screen        screen
	fileCursor    int

	// current is the open file's index; sections is its outline.
	current       int
	sections      []policyauthor.Section
	sectionCursor int
	fieldCursor   int
	focus         pane

	// page is the scrollable view shown on the explain, compare and help
	// screens; problemCursor and pickCursor select in the problems list and
	// the compare file picker.
	page          page
	problemCursor int
	pickCursor    int

	status string
}

// New returns a model for ws. lookup supplies ASA metadata for display units
// and may be nil; diagnostics, when not nil, collects the messages lookup
// reports. A workspace of one file opens straight on that file.
func New(ws *policyauthor.Workspace, lookup policyauthor.AssetLookup, diagnostics *[]string) Model {
	if diagnostics == nil {
		diagnostics = new([]string)
	}
	m := Model{ws: ws, lookup: lookup, diagnostics: diagnostics, styles: newStyles(), width: 100, height: 30}
	if len(ws.Files) == 1 {
		m = m.open(0)
	}
	return m
}

func (m Model) Init() tea.Cmd { return nil }

// problemsFor returns a file's problems and the workspace rules it breaks.
func (m Model) problemsFor(f *policyauthor.File) []policyauthor.Problem {
	out := append([]policyauthor.Problem(nil), f.Problems...)
	for _, p := range m.ws.Problems {
		if p.Path == f.Path {
			out = append(out, p)
		}
	}
	return out
}

func (m Model) open(i int) Model {
	m.current = i
	f := m.ws.Files[i]
	m.sections = policyauthor.Outline(f, m.problemsFor(f), m.lookup)
	m.sectionCursor, m.fieldCursor, m.focus = 0, 0, paneOutline
	m.screen = screenDocument
	return m
}

func (m Model) file() *policyauthor.File { return m.ws.Files[m.current] }

// reload reads the workspace from disk again, keeping the open file and the
// cursor where they are when the file is still there.
func (m Model) reload() Model {
	ws, err := policyauthor.Open(m.ws.Paths...)
	if err != nil {
		m.status = "Reload failed: " + err.Error()
		return m
	}
	var openPath string
	if m.screen == screenDocument {
		openPath = m.file().Path
	}
	section, field := m.sectionCursor, m.fieldCursor
	m.ws = ws
	m.fileCursor = min(m.fileCursor, max(0, len(ws.Files)-1))
	m.status = "Reloaded from disk"
	if openPath == "" {
		return m
	}
	for i, f := range ws.Files {
		if f.Path == openPath {
			m = m.open(i)
			m.sectionCursor = min(section, len(m.sections)-1)
			m.fieldCursor = min(field, max(0, len(m.sections[m.sectionCursor].Fields)-1))
			return m
		}
	}
	m.screen = screenFiles
	m.status = filepath.Base(openPath) + " is no longer in the workspace"
	return m
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.screen != screenFiles {
			m.status = ""
		}
		switch m.screen {
		case screenFiles:
			return m.filesKeys(msg)
		case screenDocument:
			return m.documentKeys(msg)
		case screenProblems:
			return m.problemsKeys(msg)
		case screenComparePick:
			return m.comparePickKeys(msg)
		case screenExplain, screenCompare, screenHelp, screenField:
			return m.pageKeys(msg)
		}
	}
	return m, nil
}

func (m Model) filesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		m.fileCursor = max(0, m.fileCursor-1)
	case "down", "j":
		m.fileCursor = min(len(m.ws.Files)-1, m.fileCursor+1)
	case "enter", "right", "l":
		if len(m.ws.Files) > 0 {
			m.status = ""
			return m.open(m.fileCursor), nil
		}
	case "r":
		return m.reload(), nil
	}
	return m, nil
}

func (m Model) documentKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "esc":
		if m.focus == paneForm {
			m.focus = paneOutline
			return m, nil
		}
		if len(m.ws.Files) == 1 {
			return m, tea.Quit
		}
		m.screen = screenFiles
		m.fileCursor = m.current
		return m, nil
	case "tab":
		if m.focus == paneOutline {
			m.focus = paneForm
		} else {
			m.focus = paneOutline
		}
	case "left", "h":
		m.focus = paneOutline
	case "right", "l", "enter":
		if m.focus == paneOutline && len(m.sections[m.sectionCursor].Fields) > 0 {
			m.focus = paneForm
		} else if m.focus == paneForm && msg.String() == "enter" {
			return m.openField(), nil
		}
	case "up", "k":
		m = m.move(-1)
	case "down", "j":
		m = m.move(1)
	case "home", "g":
		m = m.move(-1 << 20)
	case "end", "G":
		m = m.move(1 << 20)
	case "r":
		return m.reload(), nil
	case "]":
		return m.jump(1), nil
	case "[":
		return m.jump(-1), nil
	case "p":
		return m.openProblems(), nil
	case "x":
		return m.openExplain(), nil
	case "c":
		return m.openCompare(), nil
	case "?":
		return m.openHelp(), nil
	}
	return m, nil
}

// move steps the cursor of the focused pane by delta, clamped.
func (m Model) move(delta int) Model {
	if m.focus == paneOutline {
		next := max(0, min(len(m.sections)-1, m.sectionCursor+delta))
		if next != m.sectionCursor {
			m.sectionCursor, m.fieldCursor = next, 0
		}
		return m
	}
	fields := m.sections[m.sectionCursor].Fields
	m.fieldCursor = max(0, min(len(fields)-1, m.fieldCursor+delta))
	return m
}
