// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// A new document: n asks which document (the default or a key), what it
// starts from, and its file name. It opens unsaved; s creates the file.

type newStep int

const (
	newRole newStep = iota
	newKey
	newStart
	newName
)

type newDoc struct {
	step   newStep
	back   screen
	role   noderole.Role
	choice int
	key    string
	draft  *policy.Draft
	points []policyauthor.StartingPoint
	input  textinput.Model
	err    string
}

var newRoles = []noderole.Role{noderole.RoleSigner, noderole.RoleCosigner}

func (m Model) startNew() Model {
	n := newDoc{back: m.screen, role: m.currentWS().Role}
	if n.role == "" {
		n.step = newRole
	} else {
		n.step = newKey
		n.input = m.newInput("")
	}
	m.newDoc = n
	m.screen = screenNew
	return m
}

func (m Model) newKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	n := &m.newDoc
	if msg.String() == "esc" {
		m.screen = n.back
		m.newDoc = newDoc{}
		return m, nil
	}
	switch n.step {
	case newRole:
		switch msg.String() {
		case "left", "right", "up", "down", "tab", "h", "l", "j", "k":
			n.choice = 1 - n.choice
		case "enter":
			n.role, n.step, n.input = newRoles[n.choice], newKey, m.newInput("")
		}
		return m, nil
	case newStart:
		switch msg.String() {
		case "up", "k":
			n.choice = max(0, n.choice-1)
		case "down", "j":
			n.choice = min(len(n.points)-1, n.choice+1)
		case "enter":
			d, err := n.points[n.choice].Draft(n.key)
			if err != nil {
				n.err = err.Error()
				return m, nil
			}
			name := n.key + ".json"
			n.draft, n.step, n.err, n.input = d, newName, "", m.newInput(name)
		}
		return m, nil
	}
	if msg.String() == "enter" {
		value := strings.TrimSpace(n.input.Value())
		switch n.step {
		case newKey:
			// Keys and starting points come from the documents as edited, so a
			// copy matches what is on screen and an unsaved default counts.
			ws := m.currentWS()
			if err := ws.CheckNewKey(n.role, value); err != nil {
				n.err = err.Error()
				return m, nil
			}
			n.key, n.points, n.choice, n.step, n.err = value, ws.StartingPoints(n.role), 0, newStart, ""
		case newName:
			path, err := m.ws.NewFilePath(value)
			if err != nil {
				n.err = err.Error()
				return m, nil
			}
			s, err := policyauthor.NewDocumentSession(path, n.draft)
			if err != nil {
				n.err = err.Error()
				return m, nil
			}
			m.ws = m.ws.Add(s.Loaded)
			m.sessions[path] = s
			m.newDoc = newDoc{}
			m = m.open(len(m.ws.Files) - 1)
			m.status = fmt.Sprintf("New document for %s; it is not on disk until you save it (s)", n.key)
			return m, nil
		}
		return m, nil
	}
	var cmd tea.Cmd
	n.input, cmd = n.input.Update(msg)
	n.err = ""
	return m, cmd
}

func (m Model) newView() string {
	n := m.newDoc
	var lines []string
	// focus is the line the window keeps in view: the selected starting
	// point, else the last line (the input or the error).
	focus := -1
	lines = append(lines, m.styles.title.Render("New policy document"), "")
	switch n.step {
	case newRole:
		lines = append(lines, "Which node role is it for?")
		var parts []string
		for i, r := range newRoles {
			if i == n.choice {
				parts = append(parts, m.styles.selected.Render(" "+string(r)+" "))
			} else {
				parts = append(parts, " "+string(r)+" ")
			}
		}
		lines = append(lines, strings.Join(parts, " "))
	case newKey:
		what := "an Algorand address"
		if n.role == noderole.RoleCosigner {
			what = "a Cosigner Key ID"
		}
		lines = append(lines, fmt.Sprintf("Which document? \"default\" for the node default, or %s for one key's own:", what), n.input.View())
	case newStart:
		if note := policyauthor.StartingPointsNote(n.role); note != "" {
			for _, l := range wrap("Presets: "+note, max(20, m.width-2)) {
				lines = append(lines, m.styles.subtle.Render(l))
			}
			lines = append(lines, "")
		}
		lines = append(lines, "Start from:")
		for i, p := range n.points {
			line := fmt.Sprintf("%s  — %s", p.Label, p.Summary)
			if i == n.choice {
				focus = len(lines)
				line = m.styles.selected.Render("> " + line)
			} else {
				line = "  " + line
			}
			lines = append(lines, line)
		}
	case newName:
		lines = append(lines, "File name (created in the workspace's directory):", n.input.View())
	}
	if n.err != "" {
		lines = append(lines, "", m.styles.err.Render(n.err))
	}
	for i, l := range lines {
		lines[i] = ansi.Truncate(l, m.width, "…")
	}
	if focus < 0 || n.err != "" {
		focus = len(lines) - 1
	}
	return strings.Join(window(lines, focus, max(3, m.height-2)), "\n")
}
