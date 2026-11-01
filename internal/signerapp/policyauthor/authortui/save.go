// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// Saving. s shows what the save would change against the file as loaded and
// writes only on y. The write checks the disk first; if the file changed,
// was deleted, or appeared since it was loaded, the conflict screen offers to
// reload it (discarding the edits), save the edits under another name, or
// overwrite it after seeing the disk version against the edits.

// saveState is the save flow in progress.
type saveState struct {
	conflict *policyauthor.ConflictError
	// shownDisk is the disk version the overwrite review showed; the
	// overwrite is written only if the disk still holds it.
	shownDisk []byte
	saveAs    bool
	input     textinput.Model
	err       string
}

func (m Model) startSave() Model {
	s := m.session()
	if s == nil {
		m.status = "This file is not valid JSON and cannot be edited here"
		return m
	}
	if !s.Modified() {
		m.status = "No changes to save"
		return m
	}
	m.save = saveState{}
	c := s.Review()
	var lines []string
	cur := s.Current()
	if cur.Errors() {
		lines = append(lines, m.styles.err.Render("The edited document does not pass check; it can be saved as a draft, but apadmin will refuse it."), "")
	}
	if s.Loaded.HadComments {
		lines = append(lines, m.styles.warn.Render("This file has comments, which will not be kept; move notes into description fields."), "")
	}
	if !s.Loaded.Exists {
		lines = append(lines, "A new file.", "")
	}
	lines = append(lines, m.changeLines(c, "the file as loaded")...)
	return m.openPage(screenSave, "Save "+filepath.Base(s.Loaded.Path)+"?", lines)
}

// changeLines lays out a comparison.
func (m Model) changeLines(c policyauthor.Comparison, against string) []string {
	var lines []string
	for _, line := range wrap(fmt.Sprintf("compared with %s, by %s", against, c.Mode), max(20, m.width-2)) {
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
	} else if len(c.Changes) == 0 && c.Note == "" {
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
	return lines
}

func (m Model) saveKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y":
		return m.write(false), nil
	case "n", "esc":
		m.screen = screenDocument
		return m, nil
	}
	return m.pageKeys(msg)
}

// write saves the session. A conflict opens the conflict screen.
func (m Model) write(overwrite bool) Model {
	s := m.session()
	err := s.Save(overwrite)
	var conflict *policyauthor.ConflictError
	switch {
	case errors.As(err, &conflict):
		m.save = saveState{conflict: conflict}
		m.screen = screenConflict
		return m
	case err != nil:
		m.screen = screenDocument
		m.status = "Save failed: " + err.Error()
		return m
	}
	return m.saved(s.Loaded.Path)
}

func (m Model) saved(path string) Model {
	m.screen = screenDocument
	m.save = saveState{}
	m = m.relayout()
	name := filepath.Base(path)
	m.status = fmt.Sprintf("Saved %s. To review and install it on the node: apadmin policy diff %s, then apadmin policy apply %s", name, name, name)
	return m
}

func (m Model) conflictKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.save.saveAs {
		switch msg.String() {
		case "esc":
			m.save.saveAs, m.save.err = false, ""
			return m, nil
		case "enter":
			return m.saveAs(m.save.input.Value()), nil
		}
		var cmd tea.Cmd
		m.save.input, cmd = m.save.input.Update(msg)
		m.save.err = ""
		return m, cmd
	}
	switch msg.String() {
	case "r":
		return m.discardAndReload(), nil
	case "a":
		m.save.saveAs = true
		m.save.input = m.newInput(suggestCopy(m.session().Loaded.Path))
	case "o":
		return m.reviewOverwrite(), nil
	case "esc", "n":
		m.screen = screenDocument
		m.save = saveState{}
	}
	return m, nil
}

func suggestCopy(path string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + ".mine" + ext
}

// reviewOverwrite shows the file on disk now against the edits, so the
// operator sees what an overwrite discards. A disk file that is not JSON is
// shown as a line diff.
func (m Model) reviewOverwrite() Model {
	s := m.session()
	conflict, disk, err := s.Loaded.DiskState()
	if err != nil {
		m.status = "Cannot read the file: " + err.Error()
		return m
	}
	if conflict == policyauthor.ConflictNone {
		// The disk is back to what was loaded: an ordinary save.
		return m.write(false)
	}
	m.save.shownDisk = disk
	var lines []string
	if disk == nil {
		lines = append(lines, "The file was deleted from disk. Writing recreates it with the edits.", "")
	} else {
		onDisk := policyauthor.ParseBytes(s.Loaded.Path, disk)
		lines = append(lines, "These differences are what the overwrite replaces.", "")
		lines = append(lines, m.changeLines(policyauthor.Compare(onDisk, s.Current()), "the file as it is on disk now")...)
	}
	m = m.openPage(screenOverwrite, "Overwrite "+filepath.Base(s.Loaded.Path)+"?", lines)
	return m
}

func (m Model) overwriteKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y":
		s := m.session()
		_, disk, err := s.Loaded.DiskState()
		if err != nil {
			m.status = "Cannot read the file: " + err.Error()
			return m, nil
		}
		if string(disk) != string(m.save.shownDisk) || (disk == nil) != (m.save.shownDisk == nil) {
			// The file changed again while the review was open: show it again.
			next := m.reviewOverwrite()
			next.status = "The file changed on disk again; review the differences again"
			return next, nil
		}
		return m.write(true), nil
	case "n", "esc":
		m.screen = screenConflict
		return m, nil
	}
	return m.pageKeys(msg)
}

// discardAndReload drops the open file's edits and loads it from disk.
func (m Model) discardAndReload() Model {
	path := m.ws.Files[m.current].Path
	delete(m.sessions, path)
	f := policyauthor.LoadFile(path)
	ws := m.ws.With(m.current, f)
	m.ws = ws
	m.save = saveState{}
	m = m.open(m.current)
	m.status = "Reloaded " + filepath.Base(path) + " from disk; the edits were discarded"
	return m
}

// saveAs writes the edits to a new file, which joins the workspace and
// becomes the open file; the original file is left as it is on disk.
func (m Model) saveAs(path string) Model {
	path = strings.TrimSpace(path)
	if path == "" {
		m.save.err = "enter a file name"
		return m
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(m.session().Loaded.Path), path)
	}
	if _, err := os.Lstat(path); err == nil {
		m.save.err = path + " already exists"
		return m
	}
	s := m.session()
	old := m.ws.Files[m.current].Path
	if err := s.SaveAs(path); err != nil {
		m.save.err = err.Error()
		return m
	}
	delete(m.sessions, old)
	m.sessions[path] = s
	files := append(append([]*policyauthor.File(nil), m.ws.Files...), s.Loaded)
	ws := *m.ws
	ws.Files = files
	if !m.coversPath(path) {
		ws.Paths = append(append([]string(nil), ws.Paths...), path)
	}
	m.ws = ws.With(len(files)-1, s.Loaded)
	// The original file goes back to what is on disk, with no edits.
	m.ws = m.ws.With(m.current, policyauthor.LoadFile(old))
	m.current = len(files) - 1
	return m.saved(path)
}

// coversPath reports whether reopening the workspace would load path.
func (m Model) coversPath(path string) bool {
	for _, p := range m.ws.Paths {
		if p == path {
			return true
		}
		if info, err := os.Stat(p); err == nil && info.IsDir() && filepath.Dir(path) == filepath.Clean(p) {
			return true
		}
	}
	return false
}

func (m Model) conflictView() string {
	c := m.save.conflict
	var b strings.Builder
	b.WriteString(m.styles.title.Render("Not saved: "+filepath.Base(c.Path)+" was "+c.Kind.String()) + "\n\n")
	for _, line := range wrap("Another program changed the file after it was loaded. Choose what to do with your edits:", max(20, m.width-2)) {
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")
	b.WriteString("  r  reload the file from disk, discarding your edits\n")
	b.WriteString("  a  save your edits to a new file, leaving this one as it is\n")
	b.WriteString("  o  overwrite it, after seeing what the overwrite replaces\n")
	b.WriteString("  esc  back to editing\n")
	if m.save.saveAs {
		b.WriteString("\nSave as:\n" + m.save.input.View() + "\n")
		if m.save.err != "" {
			b.WriteString(m.styles.err.Render(m.save.err) + "\n")
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// Quitting with unsaved edits asks first.

func (m Model) quit() (tea.Model, tea.Cmd) {
	if m.unsaved() && !m.quitConfirm {
		m.quitConfirm = true
		return m, nil
	}
	return m, tea.Quit
}

func (m Model) quitKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "y" {
		return m, tea.Quit
	}
	m.quitConfirm = false
	return m, nil
}

func (m Model) unsavedCount() int {
	n := 0
	for _, s := range m.sessions {
		if s.Modified() {
			n++
		}
	}
	return n
}
