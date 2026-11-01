// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// Saving. s shows what the save would change against the file as loaded and
// writes only on y. A new file has nothing loaded to compare with, so it is
// compared with a comparison reference: the workspace default to start with,
// or any workspace file, or none, chosen with b. The reference is a local
// file, not the node's policy, and never changes what is written or what the
// conflict check compares the disk with. The write checks the disk first; if
// the file changed, was deleted, or appeared since it was loaded, the
// conflict screen offers to reload it (discarding the edits), save the edits
// under another name, or overwrite it after seeing the disk version against
// the edits.

// saveState is the save flow in progress.
type saveState struct {
	conflict *policyauthor.ConflictError
	// shownDisk is the disk version the overwrite review showed; the
	// overwrite is written only if the disk still holds it.
	shownDisk []byte
	saveAs    bool
	input     textinput.Model
	err       string
	// baseline is a new file's comparison reference, by path; "" is none.
	// pick is the reference picker's row.
	baseline string
	pick     int
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
	if !s.Loaded.Exists {
		m.save.baseline = m.defaultBaseline()
	}
	return m.saveReview()
}

// defaultBaseline is the comparison reference a new key document starts
// with: the workspace's one default, when it is for the same role.
func (m Model) defaultBaseline() string {
	cur := m.session().Current()
	def := m.currentWS().Default()
	if def == nil || def.Path == m.session().Loaded.Path || cur.Key == policy.DefaultKey || def.Role != cur.Role {
		return ""
	}
	return def.Path
}

// saveReview shows the save review: an existing file against the file as
// loaded, a new one against its comparison reference.
func (m Model) saveReview() Model {
	s := m.session()
	cur := s.Current()
	var lines []string
	if m.failsCheck() {
		lines = append(lines, m.styles.err.Render("The edited document does not pass check; it can be saved as a draft, but apadmin will refuse it."), "")
	}
	if s.Loaded.HadComments {
		lines = append(lines, m.styles.warn.Render("This file has comments, which will not be kept; move notes into description fields."), "")
	}
	title := "Save " + filepath.Base(s.Loaded.Path) + "?"
	if s.Loaded.Exists {
		lines = append(lines, m.changeLines(s.Review(), "the file as loaded")...)
		return m.openPage(screenSave, title, lines)
	}
	lines = append(lines, "A new file.", "")
	width := max(20, m.width-2)
	if m.save.baseline != "" {
		if j := m.fileIndex(m.save.baseline); j < 0 {
			for _, line := range wrap("The comparison reference "+filepath.Base(m.save.baseline)+" is no longer in the workspace; press b to choose another.", width) {
				lines = append(lines, m.styles.warn.Render(line))
			}
			lines = append(lines, "")
			m.save.baseline = ""
		} else {
			lines = append(lines, m.changeLines(policyauthor.Compare(m.shownFile(j), cur), "the comparison reference "+m.baselineLabel(j))...)
			lines = append(lines, "")
			for _, line := range wrap("The comparison reference is a file in this workspace, not the node's policy: the policy the node runs for this key now is unknown. Press b to choose another reference.", width) {
				lines = append(lines, m.styles.subtle.Render(line))
			}
			return m.openPage(screenSave, title, lines)
		}
	}
	for _, line := range wrap("New document; the policy the node runs for this key now is unknown and no comparison reference is selected, so there is nothing to compare it with. Read it with explain (x) before saving, or press b to compare it with a workspace file.", width) {
		lines = append(lines, m.styles.warn.Render(line))
	}
	return m.openPage(screenSave, title, lines)
}

// fileIndex is the index of the workspace file at path, or -1.
func (m Model) fileIndex(path string) int {
	for i, f := range m.ws.Files {
		if f.Path == path {
			return i
		}
	}
	return -1
}

// baselineLabel names workspace file i as a comparison reference.
func (m Model) baselineLabel(i int) string {
	label := filepath.Base(m.ws.Files[i].Path)
	if def := m.currentWS().Default(); def != nil && def.Path == m.ws.Files[i].Path {
		label = "the workspace default (" + label + ")"
	}
	if s, ok := m.sessions[m.ws.Files[i].Path]; ok && s.Modified() {
		label += ", as edited and not saved"
	}
	return label
}

// baselineRows are the reference picker's choices: every other workspace
// file, by index, then -1 for no comparison.
func (m Model) baselineRows() []int {
	var rows []int
	for i := range m.ws.Files {
		if i != m.current {
			rows = append(rows, i)
		}
	}
	return append(rows, -1)
}

func (m Model) openBaselinePick() Model {
	if m.session().Loaded.Exists {
		m.status = "An existing file is always compared with the file as loaded"
		return m
	}
	rows := m.baselineRows()
	m.save.pick = len(rows) - 1
	for r, i := range rows {
		if i >= 0 && m.ws.Files[i].Path == m.save.baseline {
			m.save.pick = r
		}
	}
	m.screen = screenBaselinePick
	return m
}

func (m Model) baselinePickKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.baselineRows()
	switch msg.String() {
	case "esc":
		return m.saveReview(), nil
	case "up", "k":
		m.save.pick = max(0, m.save.pick-1)
	case "down", "j":
		m.save.pick = min(len(rows)-1, m.save.pick+1)
	case "enter":
		m.save.baseline = ""
		if i := rows[m.save.pick]; i >= 0 {
			m.save.baseline = m.ws.Files[i].Path
		}
		return m.saveReview(), nil
	}
	return m, nil
}

func (m Model) baselinePickView() string {
	var b strings.Builder
	b.WriteString(m.styles.title.Render("Compare the new "+filepath.Base(m.session().Loaded.Path)+" with") + "\n\n")
	var lines []string
	for r, i := range m.baselineRows() {
		line := "(no comparison)"
		if i >= 0 {
			f := m.shownFile(i)
			key, role := f.Key, string(f.Role)
			if key == "" {
				key = "(no key)"
			}
			if role == "" {
				role = "(no role)"
			}
			line = fmt.Sprintf("%-28s %-9s %-10s %s", filepath.Base(f.Path), role, f.State, key)
			if s, ok := m.sessions[f.Path]; ok && s.Modified() {
				line += "  (edited, not saved)"
			}
		}
		line = ansi.Truncate(line, m.width-2, "…")
		if r == m.save.pick {
			line = m.styles.selected.Render("> " + line)
		} else {
			line = "  " + line
		}
		lines = append(lines, line)
	}
	b.WriteString(strings.Join(window(lines, m.save.pick, m.listHeight()), "\n"))
	return b.String()
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
	case "b":
		return m.openBaselinePick(), nil
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

// suggestCopy names a copy beside path. Save as reads a relative name
// against the file's directory, so the suggestion is the bare name.
func suggestCopy(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext) + ".mine" + ext
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
		b.WriteString("\nSave as (a name in the file's directory, or a full path):\n" + m.save.input.View() + "\n")
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
