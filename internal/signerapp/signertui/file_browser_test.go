// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
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
	m.cosigner.exportPath = filepath.Join(root, "mine.aplane-cosigner.json")
	m.cosigner.exportFocus = 1
	m = press(t, m, "ctrl+o", "enter")
	if want := filepath.Join(root, "mine.aplane-cosigner.json"); m.cosigner.exportPath != want || m.cosigner.exportFocus != 0 {
		t.Fatalf("path %q focus %d, want %q on the path field", m.cosigner.exportPath, m.cosigner.exportFocus, want)
	}
}

func TestFileBrowserCosignerImportSuggestsName(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lab.aplane-cosigner.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := Model{viewState: ViewCosignerImportForm}
	m.cosigner.importPath = root + string(filepath.Separator)
	m.cosigner.importFocus = 2
	m = press(t, m, "ctrl+o")
	m = press(t, selectBrowserEntry(t, m, "lab.aplane-cosigner.json"), "enter")
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

func TestFileBrowserFillsContractAdminParameter(t *testing.T) {
	defer setServerKeyTypes(nil)
	path, publicKeyHex := writeContractAdminReference(t)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.falcon1024-allowlist-alock.v1",
		DisplayName: "Falcon Bounded Allowlist",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:      "bounded_admin_public_key",
			Label:     "Contract Admin Public Key",
			Type:      "bytes",
			MaxLength: witness.Falcon1024PublicKeySize * 2,
		}},
	}})
	dir := filepath.Dir(path)
	m := Model{
		viewState: ViewGenerateParams,
		forms: formsState{
			genericLSigParams:     map[string]string{"bounded_admin_public_key": dir + string(filepath.Separator)},
			genericLSigParamModes: map[string]int{"bounded_admin_public_key": 0},
			generateError:         "stale",
		},
	}
	if footer := m.viewFooterText(); !strings.Contains(footer, "ctrl+o: Browse") {
		t.Fatalf("footer %q does not offer the browser on the reference field", footer)
	}
	m = press(t, m, "ctrl+o")
	if !m.fileBrowserOpen() || m.browser.dir != dir {
		t.Fatalf("ctrl+o: open %v dir %q, want %q", m.fileBrowserOpen(), m.browser.dir, dir)
	}
	m = press(t, selectBrowserEntry(t, m, filepath.Base(path)), "enter")
	if got := m.forms.genericLSigParams["bounded_admin_public_key"]; got != path || m.forms.generateError != "" {
		t.Fatalf("parameter %q error %q, want %q and no error", got, m.forms.generateError, path)
	}
	params, err := m.applyInputModeTransforms(getParamSpecForKeyType("aplane.falcon1024-allowlist-alock.v1").Params)
	if err != nil {
		t.Fatalf("applyInputModeTransforms() error = %v", err)
	}
	if params["bounded_admin_public_key"] != publicKeyHex {
		t.Fatal("the chosen reference did not resolve to its public key")
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
