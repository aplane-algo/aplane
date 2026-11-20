// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// fitsMinSizeForTest renders m at the minimum window and fails on a line
// wider than it or a view taller than it.
func fitsMinSizeForTest(t *testing.T, m Model) string {
	t.Helper()
	m = sizedForTest(t, m, MinWidth, MinHeight)
	view := stripANSI(m.View())
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > MinWidth {
			t.Errorf("line wider than the window: %q", line)
		}
	}
	if lines := strings.Count(view, "\n") + 1; lines > MinHeight {
		t.Errorf("view is %d lines, taller than the window:\n%s", lines, view)
	}
	return view
}

// squeezeForTest collapses a view's whitespace, borders included, so a test
// reads rows without their column padding.
func squeezeForTest(view string) string {
	return strings.Join(strings.Fields(strings.NewReplacer("║", " ", "│", " ").Replace(view)), " ")
}

const longSkipReason = `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "salt_counter"; restore or regenerate the key file using the current key schema`

// A preview lists the keys the archive holds that the node cannot admit
// after the rest, with the reason, before the operator confirms. They are
// never selected; the highlighted one's reason is shown in full.
func TestRestorePreviewShowsSkippedKeysBeforeConfirming(t *testing.T) {
	m := Model{
		viewState: ViewRestorePassphrase,
		restore:   restoreState{archivePath: "aplane-backup.tar.gz", passphrase: []byte("export-passphrase"), previewing: true, pendingID: "preview-1"},
	}
	m = updateModel(t, m, RestorePreviewMsg{
		ID: "preview-1", ArchivePath: "aplane-backup.tar.gz",
		Keys:    []RestoreKeyInfo{{Address: "GOODADDR", KeyType: "ed25519"}},
		Skipped: []RestoreSkipped{{Selector: "BADADDR", Reason: longSkipReason}},
	})
	if m.viewState != ViewRestorePreview {
		t.Fatalf("viewState = %v, want ViewRestorePreview", m.viewState)
	}
	if got := m.selectedRestoreAddresses(); len(got) != 1 || got[0] != "GOODADDR" {
		t.Fatalf("selected = %q, want only GOODADDR", got)
	}
	view := squeezeForTest(fitsMinSizeForTest(t, m))
	for _, want := range []string{"Selected: 1 of 1 Skipped: 1", "GOODADDR", "BADADDR skipped: failed to parse"} {
		if !strings.Contains(view, want) {
			t.Fatalf("%q missing from:\n%s", want, view)
		}
	}

	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")})
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if got := m.selectedRestoreAddresses(); len(got) != 1 || got[0] != "GOODADDR" {
		t.Fatalf("selected = %q, want only GOODADDR", got)
	}
	view = squeezeForTest(fitsMinSizeForTest(t, m))
	if !strings.Contains(view, `Skipped: failed to parse backup credential: incompatible key file format`) {
		t.Fatalf("the highlighted skipped key's reason is missing from:\n%s", view)
	}
}

// A preview whose keys are all skipped shows them, and refuses to restore.
func TestRestorePreviewWithNothingToRestore(t *testing.T) {
	m := Model{
		viewState: ViewRestorePassphrase,
		restore:   restoreState{archivePath: "aplane-backup.tar.gz", passphrase: []byte("export-passphrase"), previewing: true, pendingID: "preview-1"},
	}
	m = updateModel(t, m, RestorePreviewMsg{
		ID: "preview-1", ArchivePath: "aplane-backup.tar.gz",
		Skipped: []RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
	})
	if m.viewState != ViewRestorePreview {
		t.Fatalf("viewState = %v, want ViewRestorePreview", m.viewState)
	}
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyTab})
	next, cmd := m.handleRestorePreviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if cmd != nil || m.viewState != ViewRestorePreview || m.restore.previewError != "Nothing to restore: every key in this backup is skipped" {
		t.Fatalf("restore with nothing to restore: view %v, error %q, cmd %v", m.viewState, m.restore.previewError, cmd != nil)
	}
	view := squeezeForTest(fitsMinSizeForTest(t, m))
	for _, want := range []string{"Selected: 0 of 0 Skipped: 1", "BADADDR skipped: failed to parse", "Nothing to restore"} {
		if !strings.Contains(view, want) {
			t.Fatalf("%q missing from:\n%s", want, view)
		}
	}
}

// Many skipped keys scroll with the rest, and the view keeps the minimum
// size whichever row is highlighted.
func TestRestorePreviewWithManySkippedKeysFitsAtMinSize(t *testing.T) {
	m := Model{viewState: ViewRestorePreview, restore: restoreState{
		previewKeys: []RestoreKeyInfo{{Address: fmt.Sprintf("%058d", 0), KeyType: "aplane.falcon1024-allowlist-wide.v1"}},
		selected:    map[string]bool{fmt.Sprintf("%058d", 0): true},
	}}
	for i := 1; i <= 20; i++ {
		m.restore.previewSkipped = append(m.restore.previewSkipped, RestoreSkipped{Selector: fmt.Sprintf("%058d", i), Reason: strings.Repeat(longSkipReason+" ", 4)})
	}
	m = sizedForTest(t, m, MinWidth, MinHeight)
	for step := range 21 {
		view := fitsMinSizeForTest(t, m)
		for _, want := range []string{"RESTORE", "╚", "Skipped: 20", "> "} {
			if !strings.Contains(view, want) {
				t.Fatalf("row %d: %q missing from:\n%s", step, want, view)
			}
		}
		m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
}

// The result screen lists the keys the restore activated, then the keys it
// skipped, from the preview and from the restore.
func TestRestoreResultListsActivatedAndSkippedKeys(t *testing.T) {
	m := Model{viewState: ViewRestoring, restore: restoreState{
		archivePath:    "aplane-backup.tar.gz",
		previewSkipped: []RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
	}}
	m = updateModel(t, m, RestoreBackupResultMsg{Result: protocol.RestoreBackupResultMessage{
		Success:          true,
		Restored:         []protocol.RestoreCredential{{Selector: "GOODADDR", KeyType: "ed25519"}},
		PoliciesRestored: []string{"GOODADDR"},
		Skipped:          []protocol.RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}, {Selector: "LATEADDR", Reason: "role-forbidden"}},
	}})
	if m.viewState != ViewRestoreDisplay {
		t.Fatalf("viewState = %v, want ViewRestoreDisplay", m.viewState)
	}
	view := squeezeForTest(fitsMinSizeForTest(t, m))
	for _, want := range []string{
		"Restore Complete", "Archive: aplane-backup.tar.gz", "Activated: 1", "Skipped: 2 (cannot be restored on this node)",
		"Restored keys:", "GOODADDR [ed25519] policy", "BADADDR skipped: failed to parse backup credential",
		"LATEADDR skipped: role-forbidden", "Total: 1 activated keys, 2 skipped",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("%q missing from:\n%s", want, view)
		}
	}
	if strings.Count(view, "BADADDR") != 1 {
		t.Fatalf("a key both the preview and the restore skipped is listed twice:\n%s", view)
	}
}

// An import whose archive holds keys a restore would skip names each one,
// with the reason, on the Backups page, which keeps the minimum size.
func TestBackupImportListsTheKeysARestoreWouldSkip(t *testing.T) {
	m, commit := importToCommit(t)
	reply := commitReply(commit, true, "", "")
	reply.Result.Skipped = []protocol.RestoreSkipped{
		{Selector: "BADADDR1", Reason: "failed to parse backup credential"},
		{Selector: "BADADDR2", Reason: longSkipReason},
	}
	m, _ = update(t, m, reply)
	if m.viewState != ViewBackups || m.backups.statusErr {
		t.Fatalf("committed: view %v status %q", m.viewState, m.backups.status)
	}
	for _, want := range []string{
		"Imported lab.tar.gz.", "2 key(s) in it cannot be restored on this node; a restore will skip them:",
		"BADADDR1: failed to parse backup credential", "BADADDR2: " + longSkipReason,
	} {
		if !strings.Contains(m.backups.status, want) {
			t.Fatalf("%q missing from the status %q", want, m.backups.status)
		}
	}
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "lab.tar.gz", Size: 100}}})
	if view := squeezeForTest(fitsMinSizeForTest(t, m)); !strings.Contains(view, "BADADDR1: failed to parse backup credential") {
		t.Fatalf("the Backups page does not show the skipped keys:\n%s", view)
	}
}

// A preview that lists only some of its skipped keys counts them all.
func TestRestorePreviewCountsSkippedKeysItDoesNotList(t *testing.T) {
	m := Model{
		viewState: ViewRestorePassphrase,
		restore:   restoreState{archivePath: "aplane-backup.tar.gz", passphrase: []byte("export-passphrase"), previewing: true, pendingID: "preview-1"},
	}
	m = updateModel(t, m, RestorePreviewMsg{
		ID: "preview-1", ArchivePath: "aplane-backup.tar.gz",
		Keys:           []RestoreKeyInfo{{Address: "GOODADDR", KeyType: "ed25519"}},
		Skipped:        []RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
		SkippedOmitted: 69,
	})
	if view := squeezeForTest(fitsMinSizeForTest(t, m)); !strings.Contains(view, "Selected: 1 of 1 Skipped: 70 (1 listed)") {
		t.Fatalf("the preview does not count every skipped key:\n%s", view)
	}
	m.viewState = ViewRestoring
	m = updateModel(t, m, RestoreBackupResultMsg{Result: protocol.RestoreBackupResultMessage{
		Success: true, Restored: []protocol.RestoreCredential{{Selector: "GOODADDR", KeyType: "ed25519"}},
	}})
	view := squeezeForTest(fitsMinSizeForTest(t, m))
	for _, want := range []string{"Skipped: 70 (1 listed) (cannot be restored on this node)", "Total: 1 activated keys, 70 skipped"} {
		if !strings.Contains(view, want) {
			t.Fatalf("%q missing from:\n%s", want, view)
		}
	}
}
