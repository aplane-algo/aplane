// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	tea "github.com/charmbracelet/bubbletea"
)

func editedFee(t *testing.T) (Model, string) {
	t.Helper()
	m, path := editModel(t, "signer_key_full.json")
	m = selectField(t, m, "/max_fee_microalgos")
	m, _ = press(t, m, "enter")
	m = typeText(t, clearInput(t, m), "0.5")
	m, _ = press(t, m, "enter")
	return m, path
}

func TestSaveReviewsThenWrites(t *testing.T) {
	m, path := editedFee(t)
	m, _ = press(t, m, "s")
	if out := strings.Join(strings.Fields(view(m)), " "); m.screen != screenSave || !strings.Contains(out, "loosened /max_fee_microalgos") {
		t.Fatalf("save review:\n%s", view(m))
	}
	if disk, _ := os.ReadFile(path); !bytes.Equal(disk, fixture(t, "signer_key_full.json")) {
		t.Fatal("the review wrote to disk")
	}
	m, _ = press(t, m, "y")
	if m.screen != screenDocument || m.session().Modified() || !strings.Contains(view(m), "apadmin policy diff ops.json") {
		t.Fatalf("after y: screen %v\n%s", m.screen, view(m))
	}
	disk, _ := os.ReadFile(path)
	if !strings.Contains(string(disk), `"max_fee_microalgos": "500000"`) {
		t.Fatalf("written file:\n%s", disk)
	}
	m, _ = press(t, m, "s")
	if !strings.Contains(view(m), "No changes to save") {
		t.Fatal("s with nothing to save did not say so")
	}
}

func TestSaveReviewWarns(t *testing.T) {
	commented := append([]byte("// treasury notes\n"), fixture(t, "signer_key_full.json")...)
	ws, _ := workspace(t, map[string][]byte{"ops.json": commented})
	m := New(ws, nil, nil)
	m.width, m.height = 140, 40
	m = selectField(t, m, "/reject_clawback")
	m, _ = press(t, m, "enter", "right", "enter")
	m = selectField(t, m, "/transfer_policy/routes/0/sources")
	m, _ = press(t, m, "enter")
	m = clearInput(t, m)
	m, _ = press(t, m, "enter", "s")
	out := strings.Join(strings.Fields(view(m)), " ")
	if !strings.Contains(out, "comments, which will not be kept") || !strings.Contains(out, "does not pass check") {
		t.Fatalf("save review warnings:\n%s", view(m))
	}
}

func TestSaveConflictOverwriteRechecksTheDisk(t *testing.T) {
	m, path := editedFee(t)
	other := strings.Replace(string(fixture(t, "signer_key_full.json")), `"Operations key"`, `"Changed elsewhere"`, 1)
	if err := os.WriteFile(path, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ = press(t, m, "s", "y")
	if m.screen != screenConflict || !strings.Contains(view(m), "changed on disk") {
		t.Fatalf("conflict screen:\n%s", view(m))
	}
	m, _ = press(t, m, "o")
	if out := strings.Join(strings.Fields(view(m)), " "); m.screen != screenOverwrite || !strings.Contains(out, "/description") || !strings.Contains(out, "what the overwrite replaces") {
		t.Fatalf("overwrite review:\n%s", view(m))
	}
	// The file changes again before y: the review is shown again, not written.
	again := strings.Replace(other, `"Changed elsewhere"`, `"Changed again"`, 1)
	if err := os.WriteFile(path, []byte(again), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ = press(t, m, "y")
	if disk, _ := os.ReadFile(path); string(disk) != again || m.screen != screenOverwrite || !strings.Contains(view(m), "changed on disk again") {
		t.Fatalf("y after a second change wrote or left the review (screen %v)", m.screen)
	}
	m, _ = press(t, m, "y")
	disk, _ := os.ReadFile(path)
	if !strings.Contains(string(disk), `"500000"`) || strings.Contains(string(disk), "Changed again") || m.screen != screenDocument {
		t.Fatalf("overwrite did not write the edits:\n%s", disk)
	}
}

func TestSaveConflictShowsTextForAnUnparsableDiskFile(t *testing.T) {
	m, path := editedFee(t)
	if err := os.WriteFile(path, []byte("{ half written"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ = press(t, m, "s", "y", "o")
	if out := strings.Join(m.page.lines, "\n"); m.screen != screenOverwrite || !strings.Contains(out, "by text") || !strings.Contains(out, "removed    line 1: { half written") {
		t.Fatalf("overwrite review of an unparsable file:\n%s", out)
	}
}

func TestSaveConflictDeletedReloadAndSaveAs(t *testing.T) {
	m, path := editedFee(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	m, _ = press(t, m, "s", "y")
	if !strings.Contains(view(m), "deleted from disk") {
		t.Fatalf("deleted conflict:\n%s", view(m))
	}
	m, _ = press(t, m, "o")
	if !strings.Contains(view(m), "recreates it") {
		t.Fatalf("overwrite of a deleted file:\n%s", view(m))
	}
	m, _ = press(t, m, "y")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the file was not recreated")
	}

	// Reload discards the edits.
	m, path = editedFee(t)
	_ = os.WriteFile(path, fixture(t, "signer_default.json"), 0o600)
	m, _ = press(t, m, "s", "y", "r")
	if m.screen != screenDocument || m.shown().Key != "default" || !strings.Contains(view(m), "edits were discarded") {
		t.Fatalf("reload: key %q\n%s", m.shown().Key, view(m))
	}

	// Save as writes a new file and leaves the changed one alone.
	m, path = editedFee(t)
	changed := append(fixture(t, "signer_key_full.json"), ' ')
	_ = os.WriteFile(path, changed, 0o600)
	m, _ = press(t, m, "s", "y", "a")
	m = typeText(t, clearInput(t, m), "ops-mine.json")
	m, _ = press(t, m, "enter")
	copyPath := filepath.Join(filepath.Dir(path), "ops-mine.json")
	written, err := os.ReadFile(copyPath)
	if err != nil || !strings.Contains(string(written), `"500000"`) {
		t.Fatalf("save as: %v", err)
	}
	if disk, _ := os.ReadFile(path); !bytes.Equal(disk, changed) {
		t.Fatal("save as changed the original file")
	}
	if filepath.Base(m.file().Path) != "ops-mine.json" || len(m.ws.Files) != 2 || m.unsaved() {
		t.Fatalf("after save as: open %s, %d files, unsaved %v", m.file().Path, len(m.ws.Files), m.unsaved())
	}
	m, _ = press(t, m, "s", "y", "a")
	if m.screen == screenConflict {
		t.Fatal("save with no changes reached the conflict screen")
	}
}

func TestQuitAsksAboutUnsavedEdits(t *testing.T) {
	m, _ := editedFee(t)
	m, cmd := press(t, m, "q")
	if quits(cmd) || !strings.Contains(view(m), "unsaved edits. Quit and discard them?") {
		t.Fatalf("q with unsaved edits:\n%s", view(m))
	}
	m, cmd = press(t, m, "n")
	if quits(cmd) || m.quitConfirm {
		t.Fatal("n did not stay")
	}
	m, _ = press(t, m, "q")
	if _, cmd = press(t, m, "y"); !quits(cmd) {
		t.Fatal("y did not quit")
	}
	m, _ = press(t, m, "n", "u")
	if _, cmd = press(t, m, "q"); !quits(cmd) {
		t.Fatal("q with nothing unsaved did not quit at once")
	}
}

// TestSaveAsSuggestionWorksForARelativeWorkspace: accepting the suggested
// name saves beside the file, however the workspace was named.
func TestSaveAsSuggestionWorksForARelativeWorkspace(t *testing.T) {
	root := t.TempDir()
	doc := fixture(t, "signer_key_full.json")
	if err := os.Mkdir(filepath.Join(root, "policy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "policy", "ops.json"), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	ws, err := policyauthor.Open("policy/ops.json")
	if err != nil {
		t.Fatal(err)
	}
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	m := next.(Model)
	m = selectField(t, m, "/reject_clawback")
	m, _ = press(t, m, " ")
	_ = os.WriteFile(filepath.Join(root, "policy", "ops.json"), append(doc, ' '), 0o600)
	m, _ = press(t, m, "s", "y", "a")
	if m.save.input.Value() != "ops.mine.json" {
		t.Fatalf("suggestion %q", m.save.input.Value())
	}
	m, _ = press(t, m, "enter")
	if _, err := os.Stat(filepath.Join(root, "policy", "ops.mine.json")); err != nil || m.save.err != "" {
		t.Fatalf("save as with the suggestion: %v / %q", err, m.save.err)
	}
}
