// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	tea "github.com/charmbracelet/bubbletea"
)

func reviewText(m Model) string {
	return strings.Join(strings.Fields(strings.Join(m.page.lines, " ")), " ")
}

// newKeyDocument opens a new, unsaved key document from the shipped default
// and its save review.
func newKeyDocument(t *testing.T, m Model) Model {
	t.Helper()
	m, _ = press(t, m, "n")
	m = typeText(t, m, newKeyAddress)
	m, _ = press(t, m, "enter", "enter", "enter", "s")
	if m.screen != screenSave {
		t.Fatalf("no save review for the new document:\n%s", view(m))
	}
	return m
}

// A new file's comparison reference starts as the workspace default and can
// be any workspace file, as edited, or none. It changes only the review: the
// file written and the conflict baseline stay the new file's own.
func TestNewFileComparisonReference(t *testing.T) {
	ws, dir := workspace(t, map[string][]byte{
		"default.json": fixture(t, "signer_default.json"),
		"ops.json":     fixture(t, "signer_key_full.json"),
	})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	m := next.(Model)
	m, _ = press(t, m, "down", "enter")
	m = selectField(t, m, "/max_fee_microalgos")
	m, _ = press(t, m, "enter")
	m = typeText(t, clearInput(t, m), "0.5")
	m, _ = press(t, m, "enter")

	m = newKeyDocument(t, m)
	newPath := m.session().Loaded.Path
	if out := reviewText(m); !strings.Contains(out, "the comparison reference the workspace default (default.json)") || !strings.Contains(out, "not the node's policy") {
		t.Fatalf("the review did not start from the workspace default:\n%s", out)
	}
	if !strings.Contains(view(m), "b: Comparison reference") {
		t.Fatalf("the footer does not offer b:\n%s", view(m))
	}

	m, _ = press(t, m, "b")
	if v := view(m); m.screen != screenBaselinePick || !strings.Contains(v, "(edited, not saved)") || !strings.Contains(v, "(no comparison)") || !strings.Contains(v, "> default.json") {
		t.Fatalf("reference picker:\n%s", v)
	}
	for !strings.Contains(view(m), "> ops.json") {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "enter")
	if out := reviewText(m); m.screen != screenSave || !strings.Contains(out, "the comparison reference ops.json, as edited and not saved") || !strings.Contains(out, "/max_fee_microalgos") {
		t.Fatalf("review against the edited ops.json:\n%s", out)
	}
	// esc leaves the choice as it was.
	m, _ = press(t, m, "b", "up", "esc")
	if out := reviewText(m); !strings.Contains(out, "comparison reference ops.json") {
		t.Fatalf("esc changed the reference:\n%s", out)
	}
	m, _ = press(t, m, "b")
	for !strings.Contains(view(m), "> (no comparison)") {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "enter")
	if out := reviewText(m); !strings.Contains(out, "no comparison reference is selected") {
		t.Fatalf("no comparison:\n%s", out)
	}

	// A reference that leaves the workspace is dropped, never replaced.
	m.save.baseline = filepath.Join(dir, "ops.json")
	ws2 := *m.ws
	ws2.Files = append([]*policyauthor.File(nil), m.ws.Files...)
	for i, f := range ws2.Files {
		if filepath.Base(f.Path) == "ops.json" {
			ws2.Files = append(ws2.Files[:i], ws2.Files[i+1:]...)
			if m.current > i {
				m.current--
			}
			break
		}
	}
	m.ws = &ws2
	m = m.saveReview()
	if out := reviewText(m); !strings.Contains(out, "ops.json is no longer in the workspace") || m.save.baseline != "" {
		t.Fatalf("a removed reference: %q\n%s", m.save.baseline, out)
	}

	// Writing writes the new file, and only it.
	m.save.baseline = filepath.Join(dir, "default.json")
	m = m.saveReview()
	m, _ = press(t, m, "y")
	if m.screen != screenDocument || m.session().Loaded.Path != newPath || m.session().Modified() {
		t.Fatalf("after y: screen %v, loaded %s", m.screen, m.session().Loaded.Path)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("the new file was not written: %v", err)
	}
	for name, want := range map[string][]byte{"default.json": fixture(t, "signer_default.json"), "ops.json": fixture(t, "signer_key_full.json")} {
		if disk, _ := os.ReadFile(filepath.Join(dir, name)); !bytes.Equal(disk, want) {
			t.Fatalf("%s changed on disk", name)
		}
	}
}

func TestNewFileWithoutADefaultStartsWithNoReference(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"ops.json": fixture(t, "signer_key_full.json")})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	m := newKeyDocument(t, next.(Model))
	if out := reviewText(m); !strings.Contains(out, "nothing to compare it with") || m.save.baseline != "" {
		t.Fatalf("review with no default:\n%s", out)
	}
}

func TestExistingFileIsAlwaysComparedWithTheFileAsLoaded(t *testing.T) {
	m, _ := editedFee(t)
	m, _ = press(t, m, "s", "b")
	if m.screen != screenSave || !strings.Contains(view(m), "always compared with the file as loaded") || strings.Contains(view(m), "b: Comparison") {
		t.Fatalf("b on an existing file's review:\n%s", view(m))
	}
}

const badge = "✗ does not pass check"

// The badge follows the problems the screen shows, workspace and node
// context errors included, stays beside other messages, and ignores
// warnings.
func TestDoesNotPassCheckStatus(t *testing.T) {
	// Two files for one key: a workspace error, which the file alone lacks.
	full := fixture(t, "signer_key_full.json")
	ws, _ := workspace(t, map[string][]byte{"a.json": full, "b.json": full})
	next, _ := New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	m := next.(Model)
	m, _ = press(t, m, "enter")
	if m.shown().Errors() || !strings.Contains(view(m), badge) {
		t.Fatalf("a duplicate selector did not show the badge:\n%s", view(m))
	}

	// An asset outside the built-in table is a warning without an export,
	// and an error against a node that lacks it.
	unknown := []byte(strings.ReplaceAll(string(full), "asa:31566704", "asa:77"))
	ws, _ = workspace(t, map[string][]byte{"ops.json": unknown})
	next, _ = New(ws, nil, nil).Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	m = next.(Model)
	if len(m.problemLocations()) == 0 || strings.Contains(view(m), badge) {
		t.Fatalf("warnings alone showed the badge, or none were found:\n%s", view(m))
	}
	ctx, err := policycontext.New(noderole.RoleSigner, apconfig.DefaultGenesisHashNetworkResolver(), asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	next, _ = New(ws.WithNode(&policyauthor.NodeContext{Context: ctx, ExportedAt: time.Now(), Path: "node.json"}), nil, nil).Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	if v := view(next.(Model)); !strings.Contains(v, badge) {
		t.Fatalf("an admission error against the node did not show the badge:\n%s", v)
	}

	// Saving a draft that fails keeps the badge beside "Saved"; undo clears it.
	m, path := editModel(t, "signer_key_full.json")
	if strings.Contains(view(m), badge) {
		t.Fatalf("a valid document shows the badge:\n%s", view(m))
	}
	m = selectField(t, m, "/transfer_policy/routes/0/sources")
	m, _ = press(t, m, "enter")
	m = clearInput(t, m)
	m, _ = press(t, m, "enter", "s")
	if !strings.Contains(reviewText(m), "does not pass check") {
		t.Fatalf("the save review does not warn:\n%s", view(m))
	}
	m, _ = press(t, m, "y")
	if v := view(m); !strings.Contains(v, badge+" · Saved "+filepath.Base(path)) {
		t.Fatalf("after saving an invalid draft:\n%s", v)
	}
	m, _ = press(t, m, "u")
	if v := view(m); strings.Contains(v, badge) {
		t.Fatalf("undo back to a valid document kept the badge:\n%s", v)
	}
}
