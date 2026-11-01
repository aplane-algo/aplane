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
	screenSave
	screenBaselinePick
	screenConflict
	screenOverwrite
	screenNew
	screenTry
	screenCases
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
	// diagnostics are messages about data sources, such as the node context
	// the documents are checked against; the first is shown in the status
	// line.
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

	// sessions holds each file's edits, by path, so switching files keeps
	// them; prompt is the edit bar when one is open.
	sessions map[string]*policyauthor.Session
	prompt   prompt
	// save is the save flow; quitConfirm asks before quitting with edits
	// that are not saved.
	save        saveState
	quitConfirm bool
	newDoc      newDoc

	// networks maps genesis hashes for tries and cases; try is the try
	// form. cases are the workspace's saved cases (nil when it has none),
	// and casesErr why they could not be read.
	networks policyauthor.Networks
	try      tryForm
	cases    *policyauthor.CaseFile
	casesErr string

	status string
}

// New returns a model for ws. lookup supplies ASA metadata for display units
// and may be nil; diagnostics, when not nil, collects the messages lookup
// reports. A workspace of one file opens straight on that file.
func New(ws *policyauthor.Workspace, lookup policyauthor.AssetLookup, diagnostics *[]string) Model {
	if diagnostics == nil {
		diagnostics = new([]string)
	}
	m := Model{ws: ws, lookup: lookup, diagnostics: diagnostics, styles: newStyles(), width: 100, height: 30, sessions: map[string]*policyauthor.Session{}, networks: policyauthor.BuiltinNetworks()}
	m = m.loadCases()
	if len(ws.Files) == 1 {
		m = m.open(0)
	}
	return m
}

// WithNetworks sets the network mapping tries and saved cases use, such as
// the one a node context carries (policyauthor.NodeContext.Networks); the
// default is the built-in networks.
func (m Model) WithNetworks(n policyauthor.Networks) Model {
	m.networks = n
	return m
}

func (m Model) Init() tea.Cmd { return nil }

// problemsFor returns the problems of file i shown as f (its edited
// document, when it has one) and the workspace rules it breaks with every
// other file's edits applied too.
func (m Model) problemsFor(i int, f *policyauthor.File) []policyauthor.Problem {
	ws := m.currentWS().With(i, f)
	out := append([]policyauthor.Problem(nil), f.Problems...)
	for _, p := range ws.Problems {
		if p.Path == f.Path {
			out = append(out, p)
		}
	}
	return out
}

// currentWS is the workspace as the screen shows it: every file with its
// edits applied, so its role, its keys and the rules across files reflect
// what the operator sees, saved or not.
func (m Model) currentWS() *policyauthor.Workspace {
	ws := m.ws
	for j, f := range m.ws.Files {
		if s, ok := m.sessions[f.Path]; ok {
			ws = ws.With(j, s.Current())
		}
	}
	return ws
}

// shownFile is file i as the screen shows it: edited, when it has edits.
func (m Model) shownFile(i int) *policyauthor.File {
	if s, ok := m.sessions[m.ws.Files[i].Path]; ok {
		return s.Current()
	}
	return m.ws.Files[i]
}

// unsaved reports whether any file has edits not yet saved.
func (m Model) unsaved() bool {
	for _, s := range m.sessions {
		if s.Modified() {
			return true
		}
	}
	return false
}

func (m Model) open(i int) Model {
	m.current = i
	f := m.shown()
	m.sections = policyauthor.Outline(f, m.problemsFor(i, f), m.lookup)
	m.sectionCursor, m.fieldCursor, m.focus = 0, 0, paneOutline
	m.screen = screenDocument
	m.prompt = prompt{}
	return m
}

func (m Model) file() *policyauthor.File { return m.ws.Files[m.current] }

// reload reads the workspace from disk again, keeping the open file and the
// cursor where they are when the file is still there.
func (m Model) reload() Model {
	if m.unsaved() {
		m.status = "There are unsaved edits; save or undo them before reloading"
		return m
	}
	m.sessions = map[string]*policyauthor.Session{}
	ws, err := policyauthor.Open(m.ws.Paths...)
	if err != nil {
		m.status = "Reload failed: " + err.Error()
		return m
	}
	// The node context was selected when the workspace opened; a reload
	// reads the files again, against the same node.
	ws = ws.WithNode(m.ws.Node)
	var openPath string
	if m.screen == screenDocument {
		openPath = m.file().Path
	}
	section, field := m.sectionCursor, m.fieldCursor
	m.ws = ws
	m = m.loadCases()
	m.fileCursor = max(0, min(m.fileCursor, len(ws.Files)-1))
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
		if m.quitConfirm {
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			return m.quitKeys(msg)
		}
		if msg.String() == "ctrl+c" {
			return m.quit()
		}
		if m.screen != screenFiles {
			m.status = ""
		}
		switch m.screen {
		case screenFiles:
			return m.filesKeys(msg)
		case screenDocument:
			if m.prompt.kind != promptNone {
				return m.promptKeys(msg)
			}
			return m.documentKeys(msg)
		case screenProblems:
			return m.problemsKeys(msg)
		case screenComparePick:
			return m.comparePickKeys(msg)
		case screenExplain, screenCompare, screenHelp, screenField, screenCases:
			return m.pageKeys(msg)
		case screenTry:
			return m.tryKeys(msg)
		case screenSave:
			return m.saveKeys(msg)
		case screenBaselinePick:
			return m.baselinePickKeys(msg)
		case screenConflict:
			return m.conflictKeys(msg)
		case screenOverwrite:
			return m.overwriteKeys(msg)
		case screenNew:
			return m.newKeys(msg)
		}
	}
	return m, nil
}

func (m Model) filesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return m.quit()
	case "up", "k":
		m.fileCursor--
	case "down", "j":
		m.fileCursor++
	case "enter", "right", "l":
		if m.fileCursor >= 0 && m.fileCursor < len(m.ws.Files) {
			m.status = ""
			return m.open(m.fileCursor), nil
		}
	case "r":
		return m.reload(), nil
	case "n":
		return m.startNew(), nil
	}
	m.fileCursor = max(0, min(len(m.ws.Files)-1, m.fileCursor))
	return m, nil
}

func (m Model) documentKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m.quit()
	case "esc":
		if m.focus == paneForm {
			m.focus = paneOutline
			return m, nil
		}
		if len(m.ws.Files) == 1 {
			return m.quit()
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
			return m.editField(), nil
		}
	case "v":
		if m.focus == paneForm {
			return m.openField(), nil
		}
	case " ":
		if m.focus == paneForm {
			return m.toggle(), nil
		}
	case "a":
		return m.startAdd(), nil
	case "d":
		return m.startRemove(), nil
	case "C":
		return m.startCopy(), nil
	case "s":
		return m.startSave(), nil
	case "n":
		return m.startNew(), nil
	case "u":
		return m.undo(), nil
	case "ctrl+r":
		return m.redo(), nil
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
	case "t":
		return m.startTry(), nil
	case "T":
		return m.openCases(), nil
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
