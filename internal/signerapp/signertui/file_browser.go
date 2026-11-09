// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/witness"

	tea "github.com/charmbracelet/bubbletea"
)

// A path field that names a file on this machine can open a file browser
// with ctrl+o instead of having the path typed. The browser lists one
// directory at a time and fills the field with the absolute path chosen; it
// never reads or writes the file itself, so the field's own checks still
// decide whether the path is accepted. Every loader behind these fields takes
// regular files only, so a symbolic link to a file is listed but cannot be
// chosen. A field that names a file or directory still to be created (an
// export) chooses a directory instead, and keeps the name already in the
// field.

const fileBrowserKey = "ctrl+o"

// maxFileBrowserEntries bounds one listing; a larger directory is cut and
// says so.
const maxFileBrowserEntries = 2000

// fileBrowserTarget names the path field a browser fills.
type fileBrowserTarget int

const (
	browseNone fileBrowserTarget = iota
	browsePolicyFile
	browsePolicyExportDir
	browseCosignerImportFile
	browseCosignerExportFile
	browseClientKeyFile
	browseBackupExportDir
	browseBackupImportFile
	browseBoundaryFile
)

// fileBrowserSpec is what a target asks of the browser.
type fileBrowserSpec struct {
	title string
	// chooseDir chooses the directory to create a file or directory in; the
	// field gets that directory joined with the name it already holds.
	chooseDir bool
	// fillDir makes a directory chooser fill the field with the directory
	// itself; the name it shows is the file that will be written there.
	fillDir bool
	// suffixes are the file names listed by default; empty lists every file.
	suffixes []string
}

func fileBrowserSpecFor(target fileBrowserTarget) fileBrowserSpec {
	switch target {
	case browsePolicyFile:
		return fileBrowserSpec{title: "Choose Policy File", suffixes: []string{".json"}}
	case browsePolicyExportDir:
		return fileBrowserSpec{title: "Choose Where to Export", chooseDir: true}
	case browseCosignerImportFile:
		return fileBrowserSpec{title: "Choose Cosigner Key File", suffixes: []string{witness.CosignerPublicReferenceExtension}}
	case browseCosignerExportFile:
		return fileBrowserSpec{title: "Choose Where to Save", chooseDir: true}
	case browseClientKeyFile:
		return fileBrowserSpec{title: "Choose Client Public Key", suffixes: []string{".pub"}}
	case browseBackupExportDir:
		return fileBrowserSpec{title: "Choose Where to Export", chooseDir: true, fillDir: true}
	case browseBoundaryFile:
		return fileBrowserSpec{title: "Choose Boundary File", suffixes: []string{".yaml", ".yml"}}
	case browseBackupImportFile:
		return fileBrowserSpec{title: "Choose Backup Archive", suffixes: []string{".tar.gz", ".tgz"}}
	default:
		return fileBrowserSpec{title: "Choose File"}
	}
}

// fileBrowserEntry is one row of a listing.
type fileBrowserEntry struct {
	name    string
	isDir   bool
	symlink bool
	// parent is the ".." row; here is the "save here" row of a directory
	// chooser.
	parent bool
	here   bool
}

// fileBrowserState is the open browser, if any. It belongs to the view it
// was opened from: an approval popup shown over that view leaves it in
// place, and any other change of view closes it.
type fileBrowserState struct {
	target fileBrowserTarget
	origin ViewState
	// name is the file or directory name a directory chooser keeps.
	name string

	dir        string
	entries    []fileBrowserEntry
	truncated  bool
	selected   int
	scroll     int
	showHidden bool
	showAll    bool
	err        string
}

func (b fileBrowserState) active() bool { return b.target != browseNone }

func (b fileBrowserState) spec() fileBrowserSpec { return fileBrowserSpecFor(b.target) }

// fileBrowserOpen reports whether the browser is showing: it is open and its
// view is the current one.
func (m Model) fileBrowserOpen() bool {
	return m.browser.active() && m.browser.origin == m.viewState
}

// openFileBrowser opens a browser for target at the directory current names,
// or at the target's usual place when current names none. name is the
// default for the name a directory chooser keeps.
func (m Model) openFileBrowser(target fileBrowserTarget, current, name string) Model {
	b := fileBrowserState{target: target, origin: m.viewState}
	spec := b.spec()
	start, fieldName := fileBrowserStartFromField(current)
	switch {
	case spec.fillDir:
		// The field is the directory itself; name is the file to be written
		// there. A directory that does not exist yet opens on its parent.
		b.name = name
	case spec.chooseDir:
		b.name = fieldName
		if b.name == "" {
			b.name = name
		}
	}
	candidates := []string{}
	if start != "" {
		candidates = append(candidates, start)
	}
	candidates = append(candidates, fileBrowserDefaultDirs(target)...)
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home)
	}
	candidates = append(candidates, ".")
	var firstErr error
	for _, dir := range candidates {
		if err := b.load(dir); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		firstErr = nil
		break
	}
	if firstErr != nil {
		b.err = firstErr.Error()
	}
	m.browser = b
	return m
}

// fileBrowserStartFromField is the directory a field's value lies in, and the
// name it ends with when that is not an existing directory.
func fileBrowserStartFromField(current string) (dir, name string) {
	value := strings.TrimSpace(current)
	if value == "" {
		return "", ""
	}
	expanded, err := expandHomePath(value)
	if err != nil {
		return "", ""
	}
	if info, err := os.Stat(expanded); err == nil && info.IsDir() {
		return expanded, ""
	}
	if strings.HasSuffix(value, string(filepath.Separator)) {
		return filepath.Clean(expanded), ""
	}
	return filepath.Dir(expanded), filepath.Base(expanded)
}

// fileBrowserDefaultDirs are where a target's browser starts when its field
// names no directory: the newest policy export for a policy file, ~/.ssh for
// a client key.
func fileBrowserDefaultDirs(target fileBrowserTarget) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	switch target {
	case browsePolicyFile:
		if dir := newestPolicyExportDir(home); dir != "" {
			return []string{dir}
		}
	case browseClientKeyFile:
		return []string{filepath.Join(home, ".ssh")}
	case browseBoundaryFile:
		// Boundary files and receipts belong where the operator is working.
		if dir, err := os.Getwd(); err == nil {
			return []string{dir}
		}
	}
	return nil
}

// newestPolicyExportDir is the most recently modified ~/policy-export-*
// directory, or "" when there is none.
func newestPolicyExportDir(home string) string {
	matches, err := filepath.Glob(filepath.Join(home, "policy-export-*"))
	if err != nil {
		return ""
	}
	newest := ""
	var newestTime int64
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil || !info.IsDir() {
			continue
		}
		if t := info.ModTime().UnixNano(); newest == "" || t > newestTime {
			newest, newestTime = match, t
		}
	}
	return newest
}

// load lists dir, keeping the browser where it was when dir cannot be read.
func (b *fileBrowserState) load(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	entries, truncated, err := listFileBrowserDir(abs, b.spec(), b.showHidden, b.showAll)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", abs, unwrapPathError(err))
	}
	b.dir = abs
	b.entries = entries
	b.truncated = truncated
	b.selected = 0
	b.scroll = 0
	b.err = ""
	return nil
}

// unwrapPathError drops the path from a *fs.PathError, which the message
// already names.
func unwrapPathError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// listFileBrowserDir lists dir for spec: the "save here" row of a directory
// chooser, "..", then directories, then the files spec lists, each group by
// name. Entries that are neither directories nor regular files (sockets,
// devices, pipes) are left out, as are hidden ones unless showHidden.
func listFileBrowserDir(dir string, spec fileBrowserSpec, showHidden, showAll bool) ([]fileBrowserEntry, bool, error) {
	raw, err := os.ReadDir(dir)
	if err != nil {
		return nil, false, err
	}
	var dirs, files []fileBrowserEntry
	for _, e := range raw {
		name := e.Name()
		if !showHidden && strings.HasPrefix(name, ".") {
			continue
		}
		mode := e.Type()
		entry := fileBrowserEntry{name: name}
		switch {
		case mode&fs.ModeSymlink != 0:
			entry.symlink = true
			if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.IsDir() {
				entry.isDir = true
			}
		case mode.IsDir():
			entry.isDir = true
		case mode.IsRegular():
		default:
			continue
		}
		if entry.isDir {
			dirs = append(dirs, entry)
			continue
		}
		if spec.chooseDir || (!showAll && !fileBrowserNameMatches(name, spec.suffixes)) {
			continue
		}
		files = append(files, entry)
	}
	byName := func(list []fileBrowserEntry) {
		sort.Slice(list, func(i, j int) bool {
			a, b := strings.ToLower(list[i].name), strings.ToLower(list[j].name)
			if a != b {
				return a < b
			}
			return list[i].name < list[j].name
		})
	}
	byName(dirs)
	byName(files)

	var out []fileBrowserEntry
	if spec.chooseDir {
		out = append(out, fileBrowserEntry{here: true})
	}
	if filepath.Dir(dir) != dir {
		out = append(out, fileBrowserEntry{name: "..", isDir: true, parent: true})
	}
	out = append(out, dirs...)
	out = append(out, files...)
	truncated := false
	if len(out) > maxFileBrowserEntries {
		out = out[:maxFileBrowserEntries]
		truncated = true
	}
	return out, truncated, nil
}

func fileBrowserNameMatches(name string, suffixes []string) bool {
	if len(suffixes) == 0 {
		return true
	}
	lower := strings.ToLower(name)
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func (m Model) closeFileBrowser() Model {
	m.browser = fileBrowserState{}
	return m
}

func (m Model) handleFileBrowserKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	b := &m.browser
	page := max(m.fileBrowserVisibleRows()-1, 1)
	switch msg.String() {
	case "esc", fileBrowserKey:
		return m.closeFileBrowser(), nil
	case "up", "k":
		b.move(-1)
	case "down", "j":
		b.move(1)
	case "pgup":
		b.move(-page)
	case "pgdown":
		b.move(page)
	case "home", "g":
		b.move(-len(b.entries))
	case "end", "G":
		b.move(len(b.entries))
	case "left", "h", "backspace":
		b.up()
	case "~":
		if home, err := os.UserHomeDir(); err == nil {
			if err := b.load(home); err != nil {
				b.err = err.Error()
			}
		}
	case ".":
		b.showHidden = !b.showHidden
		b.reload()
	case "a":
		if spec := b.spec(); !spec.chooseDir && len(spec.suffixes) > 0 {
			b.showAll = !b.showAll
			b.reload()
		}
	case "enter", "right", "l":
		return m.activateFileBrowserEntry()
	}
	b.keepSelectionVisible(m.fileBrowserVisibleRows())
	return m, nil
}

func (b *fileBrowserState) move(delta int) {
	if len(b.entries) == 0 {
		return
	}
	b.selected = min(max(b.selected+delta, 0), len(b.entries)-1)
	b.err = ""
}

// up opens the parent directory with the directory just left selected.
func (b *fileBrowserState) up() {
	parent := filepath.Dir(b.dir)
	if parent == b.dir {
		return
	}
	left := filepath.Base(b.dir)
	if err := b.load(parent); err != nil {
		b.err = err.Error()
		return
	}
	b.selectName(left)
}

// reload lists the directory again, keeping the selected name when it is
// still listed.
func (b *fileBrowserState) reload() {
	name := ""
	if b.selected >= 0 && b.selected < len(b.entries) {
		name = b.entries[b.selected].name
	}
	if err := b.load(b.dir); err != nil {
		b.err = err.Error()
		return
	}
	b.selectName(name)
}

func (b *fileBrowserState) selectName(name string) {
	if name == "" {
		return
	}
	for i, entry := range b.entries {
		if !entry.here && !entry.parent && entry.name == name {
			b.selected = i
			return
		}
	}
}

func (b *fileBrowserState) keepSelectionVisible(rows int) {
	if rows < 1 {
		rows = 1
	}
	if b.selected < b.scroll {
		b.scroll = b.selected
	}
	if b.selected >= b.scroll+rows {
		b.scroll = b.selected - rows + 1
	}
	maxScroll := max(len(b.entries)-rows, 0)
	b.scroll = min(max(b.scroll, 0), maxScroll)
}

// activateFileBrowserEntry opens the selected directory, or chooses the
// selected file or, in a directory chooser, the directory shown.
func (m Model) activateFileBrowserEntry() (tea.Model, tea.Cmd) {
	b := &m.browser
	if b.selected < 0 || b.selected >= len(b.entries) {
		return m, nil
	}
	entry := b.entries[b.selected]
	switch {
	case entry.here:
		if b.spec().fillDir {
			return m.chooseFileBrowserPath(b.dir), nil
		}
		return m.chooseFileBrowserPath(filepath.Join(b.dir, b.name)), nil
	case entry.parent:
		b.up()
	case entry.isDir:
		if err := b.load(filepath.Join(b.dir, entry.name)); err != nil {
			b.err = err.Error()
		}
	case entry.symlink:
		b.err = entry.name + " is a symbolic link; choose the file it points to"
	default:
		return m.chooseFileBrowserPath(filepath.Join(b.dir, entry.name)), nil
	}
	b.keepSelectionVisible(m.fileBrowserVisibleRows())
	return m, nil
}

// chooseFileBrowserPath puts path into the field the browser was opened for
// and closes the browser.
func (m Model) chooseFileBrowserPath(path string) Model {
	b := m.browser
	m = m.closeFileBrowser()
	switch b.target {
	case browsePolicyFile:
		m.policies.apply.path = path
		m.policies.apply.err = ""
		m.policies.apply.problems = nil
	case browsePolicyExportDir:
		m.policies.export.path = path
		m.policies.export.err = ""
	case browseCosignerImportFile:
		m.cosigner.importPath = path
		m.cosigner.importError = ""
		m = m.suggestCosignerImportNameFromPath()
	case browseCosignerExportFile:
		m.cosigner.exportPath = path
		m.cosigner.exportError = ""
	case browseClientKeyFile:
		m.clients.importPath = path
		m.clients.importError = ""
	case browseBackupExportDir:
		m.backups.export.dir = path
		m.backups.export.err = ""
	case browseBackupImportFile:
		m.backups.imp.path = path
		m.backups.imp.err = ""
	case browseBoundaryFile:
		m.forms.boundaryFile = path
		m.forms.generateError = ""
	}
	return m
}

// fileBrowserFixedLines are the browser's rows other than the listing: the
// title, hint, directory, blank separators, and a message row.
const fileBrowserFixedLines = 8

func (m Model) fileBrowserVisibleRows() int {
	height := m.popupContentHeight()
	if height <= 0 {
		return 15
	}
	return max(height-fileBrowserFixedLines, 3)
}

func (m Model) renderFileBrowser() string {
	b := m.browser
	rows := m.fileBrowserVisibleRows()
	// The window may have changed size since the last key; show the
	// selection whatever the stored scroll says.
	b.keepSelectionVisible(rows)
	spec := b.spec()
	width := m.popupBodyWidth(90)
	var body strings.Builder
	body.WriteString(titleStyle.Render(spec.title))
	body.WriteString("\n")
	body.WriteString(subtitleStyle.Render(ellipsize(fileBrowserHint(b, spec), width)))
	body.WriteString("\n\n")
	body.WriteString(ellipsizeMiddle(terminalSafe(b.dir), width))
	body.WriteString("\n\n")

	if len(b.entries) == 0 {
		body.WriteString(helpStyle.Render("(nothing to show here; . shows hidden entries)"))
		body.WriteString("\n")
	}
	end := min(b.scroll+rows, len(b.entries))
	for i := b.scroll; i < end; i++ {
		line := ellipsize(fileBrowserEntryLabel(b.entries[i], b.name, spec.fillDir), width-2)
		if i == b.selected {
			body.WriteString(selectedStyle.Render("> " + line))
		} else if b.entries[i].symlink && !b.entries[i].isDir {
			body.WriteString(helpStyle.Render("  " + line))
		} else {
			body.WriteString("  " + line)
		}
		body.WriteString("\n")
	}
	status := ""
	if len(b.entries) > rows {
		status = fmt.Sprintf("%d-%d of %d", b.scroll+1, end, len(b.entries))
	}
	if b.truncated {
		status = strings.TrimSpace(status + fmt.Sprintf("  (first %d entries only)", maxFileBrowserEntries))
	}
	if status != "" {
		body.WriteString(helpStyle.Render(status))
		body.WriteString("\n")
	}
	if b.err != "" {
		body.WriteString("\n")
		body.WriteString(errorStyle.Render(wrapPlainText(terminalSafe(b.err), width)))
		body.WriteString("\n")
	}
	return m.renderPopup(90, body.String())
}

func fileBrowserHint(b fileBrowserState, spec fileBrowserSpec) string {
	switch {
	case spec.fillDir:
		return "Open a directory, then choose \"Export here\"."
	case spec.chooseDir:
		return "Open a directory, then choose \"Save here\"."
	case len(spec.suffixes) > 0 && !b.showAll:
		return "Showing " + strings.Join(fileBrowserPatterns(spec.suffixes), ", ") + " files; a shows all files."
	case len(spec.suffixes) > 0:
		return "Showing all files; a shows " + strings.Join(fileBrowserPatterns(spec.suffixes), ", ") + " only."
	default:
		return "Choose a file."
	}
}

func fileBrowserPatterns(suffixes []string) []string {
	out := make([]string, len(suffixes))
	for i, s := range suffixes {
		out[i] = "*" + s
	}
	return out
}

// fileBrowserEntryLabel is an entry's row, with names escaped for the
// terminal; name is the name a "save here" row keeps.
func fileBrowserEntryLabel(entry fileBrowserEntry, name string, fillDir bool) string {
	entry.name, name = terminalSafe(entry.name), terminalSafe(name)
	switch {
	case entry.here && fillDir:
		return "[ Export here as " + name + " ]"
	case entry.here:
		return "[ Save here as " + name + " ]"
	case entry.parent:
		return "../"
	case entry.isDir && entry.symlink:
		return entry.name + "/ (link)"
	case entry.isDir:
		return entry.name + "/"
	case entry.symlink:
		return entry.name + " (link; not accepted)"
	default:
		return entry.name
	}
}

func (m Model) fileBrowserFooterText() string {
	b := m.browser
	parts := []string{"enter: Open/Choose", "left/backspace: Up", ".: Hidden", "~: Home"}
	if spec := b.spec(); !spec.chooseDir && len(spec.suffixes) > 0 {
		parts = append(parts, "a: All files")
	}
	parts = append(parts, "esc: Cancel")
	return strings.Join(parts, " | ")
}
