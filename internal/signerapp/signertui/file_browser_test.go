// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func browserKey(s string) tea.KeyMsg {
	switch s {
	case "ctrl+o":
		return tea.KeyMsg{Type: tea.KeyCtrlO}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// press sends keys through the TUI's key router, as the program would.
func press(t *testing.T, m Model, keys ...string) Model {
	t.Helper()
	for _, k := range keys {
		next, _ := m.handleKeyPress(browserKey(k))
		m = next.(Model)
	}
	return m
}

// browserTree is a directory holding a.json, b.txt, .hidden.json, sub/ with
// c.json, and link.json, a symbolic link to a.json.
func browserTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"a.json", "b.txt", ".hidden.json", filepath.Join("sub", "c.json")} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "a.json"), filepath.Join(root, "link.json")); err != nil {
		t.Fatal(err)
	}
	return root
}

func browserNames(b fileBrowserState) []string {
	var names []string
	for _, e := range b.entries {
		switch {
		case e.here:
			names = append(names, "[here]")
		case e.isDir:
			names = append(names, e.name+"/")
		default:
			names = append(names, e.name)
		}
	}
	return names
}

// selectBrowserEntry moves the selection to name with the arrow keys.
func selectBrowserEntry(t *testing.T, m Model, name string) Model {
	t.Helper()
	m = press(t, m, "g")
	for i := 0; i < len(m.browser.entries); i++ {
		e := m.browser.entries[m.browser.selected]
		if e.name == name || (e.isDir && e.name+"/" == name) {
			return m
		}
		m = press(t, m, "down")
	}
	t.Fatalf("%s is not listed: %v", name, browserNames(m.browser))
	return m
}

func policyApplyFormModel(path string) Model {
	m := Model{viewState: ViewPolicyApplyForm}
	m.policies.apply.path = path
	return m
}

func TestFileBrowserListsOnlyTheMatchingRoleReference(t *testing.T) {
	for _, test := range []struct {
		target fileBrowserTarget
		want   string
	}{
		{browseCosignerImportFile, ".cos.json"},
	} {
		spec := fileBrowserSpecFor(test.target)
		if len(spec.suffixes) != 1 || spec.suffixes[0] != test.want {
			t.Fatalf("%s suffixes = %v, want [%s]", spec.title, spec.suffixes, test.want)
		}
	}
}

func TestFileBrowserChoosesPolicyFile(t *testing.T) {
	root := browserTree(t)
	m := press(t, policyApplyFormModel(filepath.Join(root, "typed.json")), "ctrl+o")
	if !m.fileBrowserOpen() || m.browser.dir != root {
		t.Fatalf("ctrl+o: open %v dir %q, want the field's directory %q", m.fileBrowserOpen(), m.browser.dir, root)
	}
	if got, want := strings.Join(browserNames(m.browser), " "), "../ sub/ a.json link.json"; got != want {
		t.Fatalf("listing = %q, want %q (json files only, no hidden entries)", got, want)
	}
	if footer := m.viewFooterText(); !strings.Contains(footer, "a: All files") {
		t.Fatalf("footer %q does not offer all files", footer)
	}
	if view := m.renderViewContent(); !strings.Contains(view, "Choose Policy File") || !strings.Contains(view, "a.json") {
		t.Fatalf("the browser is not rendered:\n%s", view)
	}

	m = press(t, selectBrowserEntry(t, m, "a.json"), "enter")
	if m.fileBrowserOpen() || m.browser.active() {
		t.Fatal("choosing a file left the browser open")
	}
	if m.viewState != ViewPolicyApplyForm || m.policies.apply.path != filepath.Join(root, "a.json") {
		t.Fatalf("view %v path %q, want the form with the chosen file", m.viewState, m.policies.apply.path)
	}
}

func TestFileBrowserFiltersAndHiddenToggle(t *testing.T) {
	root := browserTree(t)
	m := press(t, policyApplyFormModel(root+string(filepath.Separator)), "ctrl+o", "a")
	if got, want := strings.Join(browserNames(m.browser), " "), "../ sub/ a.json b.txt link.json"; got != want {
		t.Fatalf("a: listing = %q, want %q", got, want)
	}
	m = press(t, m, "a", ".")
	if got, want := strings.Join(browserNames(m.browser), " "), "../ sub/ .hidden.json a.json link.json"; got != want {
		t.Fatalf(".: listing = %q, want %q", got, want)
	}
}

func TestFileBrowserNavigatesDirectories(t *testing.T) {
	root := browserTree(t)
	m := press(t, policyApplyFormModel(root+string(filepath.Separator)), "ctrl+o")
	m = press(t, selectBrowserEntry(t, m, "sub/"), "enter")
	if want := filepath.Join(root, "sub"); m.browser.dir != want {
		t.Fatalf("enter on sub/: dir %q, want %q", m.browser.dir, want)
	}
	m = press(t, m, "left")
	if m.browser.dir != root {
		t.Fatalf("left: dir %q, want %q", m.browser.dir, root)
	}
	if e := m.browser.entries[m.browser.selected]; e.name != "sub" {
		t.Fatalf("after going up the selection is %q, want the directory just left", e.name)
	}
	m = press(t, m, "backspace")
	if m.browser.dir != filepath.Dir(root) {
		t.Fatalf("backspace: dir %q, want %q", m.browser.dir, filepath.Dir(root))
	}
}

func TestFileBrowserRefusesSymlinkedFile(t *testing.T) {
	root := browserTree(t)
	m := press(t, policyApplyFormModel(root+string(filepath.Separator)), "ctrl+o")
	m = press(t, selectBrowserEntry(t, m, "link.json"), "enter")
	if !m.fileBrowserOpen() || !strings.Contains(m.browser.err, "symbolic link") {
		t.Fatalf("choosing a link: open %v err %q, want it refused in the browser", m.fileBrowserOpen(), m.browser.err)
	}
	if m.policies.apply.path != root+string(filepath.Separator) {
		t.Fatalf("a refused link changed the field to %q", m.policies.apply.path)
	}
}

func TestFileBrowserEscKeepsField(t *testing.T) {
	root := browserTree(t)
	typed := filepath.Join(root, "typed.json")
	m := press(t, policyApplyFormModel(typed), "ctrl+o", "esc")
	if m.browser.active() || m.viewState != ViewPolicyApplyForm || m.policies.apply.path != typed {
		t.Fatalf("esc: browser %v view %v path %q, want the form unchanged", m.browser.active(), m.viewState, m.policies.apply.path)
	}
	// esc in the form itself still leaves the form.
	m.policies.loading = true
	m = press(t, m, "esc")
	if m.viewState != ViewPolicies {
		t.Fatalf("esc in the form: view %v, want ViewPolicies", m.viewState)
	}
}

func TestFileBrowserChoosesExportDirectoryKeepingName(t *testing.T) {
	root := browserTree(t)
	m := Model{viewState: ViewPolicyExportForm}
	m.policies.export.path = filepath.Join(root, "policy-export-x")
	m = press(t, m, "ctrl+o")
	if got := browserNames(m.browser); len(got) == 0 || got[0] != "[here]" {
		t.Fatalf("listing = %v, want the save-here row first", got)
	}
	for _, name := range browserNames(m.browser) {
		if !strings.HasSuffix(name, "/") && name != "[here]" {
			t.Fatalf("a directory chooser lists the file %q", name)
		}
	}
	if view := m.renderViewContent(); !strings.Contains(view, "Save here as policy-export-x") {
		t.Fatalf("the save-here row does not name the export:\n%s", view)
	}
	m = press(t, selectBrowserEntry(t, m, "sub/"), "enter", "g", "enter")
	if want := filepath.Join(root, "sub", "policy-export-x"); m.policies.export.path != want || m.browser.active() {
		t.Fatalf("path %q browser %v, want %q", m.policies.export.path, m.browser.active(), want)
	}
}

func TestFileBrowserExportDefaultsName(t *testing.T) {
	root := t.TempDir()
	m := Model{viewState: ViewPolicyExportForm}
	m.policies.export.path = root
	m = press(t, m, "ctrl+o")
	if m.browser.dir != root || !strings.HasPrefix(m.browser.name, "policy-export-") {
		t.Fatalf("dir %q name %q, want the existing directory and a suggested export name", m.browser.dir, m.browser.name)
	}
}

func TestFileBrowserCosignerExportKeepsSuggestedName(t *testing.T) {
	root := t.TempDir()
	m := Model{viewState: ViewCosignerExportPath}
	m.cosigner.exportWitnessID = "ABCDEFGHIJKLMNOP"
	m.cosigner.exportPath = filepath.Join(root, "mine.cos.json")
	m.cosigner.exportFocus = 1
	m = press(t, m, "ctrl+o", "enter")
	if want := filepath.Join(root, "mine.cos.json"); m.cosigner.exportPath != want || m.cosigner.exportFocus != 0 {
		t.Fatalf("path %q focus %d, want %q on the path field", m.cosigner.exportPath, m.cosigner.exportFocus, want)
	}
}

func TestFileBrowserCosignerImportSuggestsName(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lab.cos.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := Model{viewState: ViewCosignerImportForm}
	m.cosigner.importPath = root + string(filepath.Separator)
	m.cosigner.importFocus = 2
	m = press(t, m, "ctrl+o")
	m = press(t, selectBrowserEntry(t, m, "lab.cos.json"), "enter")
	if m.cosigner.importPath != path || m.cosigner.importName != "lab" {
		t.Fatalf("path %q name %q, want the file and the name from it", m.cosigner.importPath, m.cosigner.importName)
	}

	// The paste form has no file to browse for.
	m = Model{viewState: ViewCosignerImportForm}
	m.cosigner.importPaste = true
	if m = press(t, m, "ctrl+o"); m.browser.active() {
		t.Fatal("ctrl+o opened a browser on the paste form")
	}
}

func TestFileBrowserClientKeyStartsInSSHDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_ed25519", "id_ed25519.pub"} {
		if err := os.WriteFile(filepath.Join(ssh, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m := Model{viewState: ViewImportClientKey}
	m.clients.importFocus = importClientKeyFocusLabel
	m = press(t, m, "ctrl+o")
	if m.browser.dir != ssh || m.clients.importFocus != importClientKeyFocusPath {
		t.Fatalf("dir %q focus %d, want ~/.ssh and the path field", m.browser.dir, m.clients.importFocus)
	}
	if got := strings.Join(browserNames(m.browser), " "); got != "../ id_ed25519.pub" {
		t.Fatalf("listing = %q, want the public key only", got)
	}
	m = press(t, selectBrowserEntry(t, m, "id_ed25519.pub"), "enter")
	if want := filepath.Join(ssh, "id_ed25519.pub"); m.clients.importPath != want {
		t.Fatalf("path %q, want %q", m.clients.importPath, want)
	}
}

func TestFileBrowserPolicyFileStartsInNewestExport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	older := filepath.Join(home, "policy-export-1")
	newer := filepath.Join(home, "policy-export-2")
	for _, dir := range []string{newer, older} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(older, past, past); err != nil {
		t.Fatal(err)
	}
	m := press(t, policyApplyFormModel(""), "ctrl+o")
	if m.browser.dir != newer {
		t.Fatalf("dir %q, want the newest export %q", m.browser.dir, newer)
	}
}

func TestFileBrowserFallsBackFromMissingDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	m := press(t, policyApplyFormModel(filepath.Join(home, "gone", "x.json")), "ctrl+o")
	if m.browser.dir != home || m.browser.err != "" {
		t.Fatalf("dir %q err %q, want home without an error", m.browser.dir, m.browser.err)
	}
}

func TestFileBrowserWaitsUnderApprovalAndClosesOnViewChange(t *testing.T) {
	root := browserTree(t)
	m := press(t, policyApplyFormModel(root+string(filepath.Separator)), "ctrl+o")

	m.viewState = ViewSigningPopup
	if m.fileBrowserOpen() || strings.Contains(m.viewFooterText(), "Hidden") {
		t.Fatal("the browser shows over an approval popup")
	}
	m = press(t, m, "down")
	if !m.browser.active() {
		t.Fatal("a key on an approval popup closed the browser beneath it")
	}
	m.viewState = ViewPolicyApplyForm
	if !m.fileBrowserOpen() {
		t.Fatal("the browser did not come back after the popup")
	}

	m.viewState = ViewPolicies
	m.policies.loading = true
	m = press(t, m, "down")
	if m.browser.active() {
		t.Fatal("leaving the form's view did not close the browser")
	}
}

func TestFileBrowserEscapesNamesButKeepsPath(t *testing.T) {
	root := t.TempDir()
	const clear = "\x1b[2J"
	name := "evil" + clear + "\u202e.json"
	if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := Model{viewState: ViewPolicyApplyForm, width: 100, height: 40}
	m.policies.apply.path = root + string(filepath.Separator)
	m = press(t, m, "ctrl+o")
	view := m.View()
	if strings.Contains(view, clear) || strings.Contains(view, "\u202e") {
		t.Fatal("the browser printed a file name's control characters")
	}
	if !strings.Contains(view, `evil\x1b[2J\u202e.json`) {
		t.Fatalf("the browser does not show the escaped name:\n%s", view)
	}

	m = press(t, selectBrowserEntry(t, m, name), "enter")
	if want := filepath.Join(root, name); m.policies.apply.path != want {
		t.Fatalf("field = %q, want the file's real path %q", m.policies.apply.path, want)
	}
	if view := m.View(); strings.Contains(view, clear) || !strings.Contains(view, `\x1b[2J`) {
		t.Fatalf("the form printed the chosen path's control characters:\n%s", view)
	}
}

func TestFileBrowserKeepsSelectionVisibleAfterResize(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 60; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%02d.json", i)), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m := Model{viewState: ViewPolicyApplyForm, width: 100, height: 40}
	m.policies.apply.path = root + string(filepath.Separator)
	m = press(t, m, "ctrl+o", "G")
	next, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	m = next.(Model)
	if view := m.View(); !strings.Contains(view, "> f59.json") {
		t.Fatalf("the selected entry is not shown after shrinking the window:\n%s", view)
	}
	if rows := m.fileBrowserVisibleRows(); m.browser.selected >= m.browser.scroll+rows {
		t.Fatalf("selected %d scroll %d rows %d: the stored scroll was not reconciled", m.browser.selected, m.browser.scroll, rows)
	}
}

func TestTerminalSafe(t *testing.T) {
	for _, tc := range []struct{ in, line, lines string }{
		{"plain name.json", "plain name.json", "plain name.json"},
		{"ünïcode ✓", "ünïcode ✓", "ünïcode ✓"},
		{"a\x1b[2Jb", `a\x1b[2Jb`, `a\x1b[2Jb`},
		{"rtl\u202eexe.json", `rtl\u202eexe.json`, `rtl\u202eexe.json`},
		{"bad\xffbyte", `bad\xffbyte`, `bad\xffbyte`},
		{"two\nlines\tand\rcr", `two\nlines\tand\rcr`, "two\nlines\tand\\rcr"},
		{"bell\a", `bell\a`, `bell\a`},
	} {
		if got := terminalSafe(tc.in); got != tc.line {
			t.Errorf("terminalSafe(%q) = %q, want %q", tc.in, got, tc.line)
		}
		if got := terminalSafeLines(tc.in); got != tc.lines {
			t.Errorf("terminalSafeLines(%q) = %q, want %q", tc.in, got, tc.lines)
		}
	}
}

func TestFileBrowserBackupImportListsArchivesOnly(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.tar.gz", "b.tgz", "c.json", "d.tar"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m := Model{viewState: ViewBackupImport}
	m.backups.imp.path = root + string(filepath.Separator)
	m = press(t, m, "ctrl+o")
	if got := strings.Join(browserNames(m.browser), " "); got != "../ a.tar.gz b.tgz" {
		t.Fatalf("listing = %q, want the archives only", got)
	}
	m = press(t, selectBrowserEntry(t, m, "b.tgz"), "enter")
	if m.backups.imp.path != filepath.Join(root, "b.tgz") {
		t.Fatalf("path = %q", m.backups.imp.path)
	}
}

func TestFileBrowserBackupExportFillsTheDirectoryItself(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "usb"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := Model{viewState: ViewBackupExport, width: 100, height: 40}
	m.backups.export = backupExportState{target: BackupInfo{FileName: "aplane-backup-x.tar.gz"}, dir: root}
	m = press(t, m, "ctrl+o")
	if view := stripANSI(m.renderViewContent()); !strings.Contains(view, "Export here as aplane-backup-x.tar.gz") {
		t.Fatalf("the chooser does not name the archive:\n%s", view)
	}
	m = press(t, selectBrowserEntry(t, m, "usb/"), "enter", "g", "enter")
	if want := filepath.Join(root, "usb"); m.backups.export.dir != want || m.browser.active() {
		t.Fatalf("dir = %q, want %q (the directory, not a file in it)", m.backups.export.dir, want)
	}
}
