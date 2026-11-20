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

// An import whose archive holds keys a restore would skip counts them on
// the Backups page and names the first few, each on one line, so the backup
// list stays in view at the minimum size.
func TestBackupImportListsTheKeysARestoreWouldSkip(t *testing.T) {
	m, commit := importToCommit(t)
	reply := commitReply(commit, true, "", "")
	for i := range 40 {
		reply.Result.Skipped = append(reply.Result.Skipped, protocol.RestoreSkipped{Selector: fmt.Sprintf("BADADDR%02d", i), Reason: longSkipReason})
	}
	reply.Result.SkippedOmitted = 5
	m, _ = update(t, m, reply)
	if m.viewState != ViewBackups || m.backups.statusErr {
		t.Fatalf("committed: view %v status %q", m.viewState, m.backups.status)
	}
	for _, want := range []string{
		"Imported lab.tar.gz.", "A restore will skip 45 key(s) in it that this node cannot use:",
		"BADADDR00: failed to parse backup credential", "BADADDR02: ", "and 42 more; the backup's preview lists them",
	} {
		if !strings.Contains(m.backups.status, want) {
			t.Fatalf("%q missing from the status %q", want, m.backups.status)
		}
	}
	if strings.Contains(m.backups.status, "BADADDR03") {
		t.Fatalf("the status lists more than the first few keys: %q", m.backups.status)
	}
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "lab.tar.gz", Size: 100}}})
	view := fitsMinSizeForTest(t, m)
	if !strings.Contains(view, "> unknown *") || !strings.Contains(view, "lab.tar.gz") || strings.Contains(view, "Panel lines") {
		t.Fatalf("the backup list is not in view:\n%s", view)
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

// A failed restore whose error wraps over four lines, with twelve skipped
// keys, keeps the popup's border, the total and the cursor's row on screen
// at the minimum size, wherever the cursor is.
func TestRestoreResultWithAWrappedErrorFitsAtMinSize(t *testing.T) {
	result := RestoreDisplayResult{
		ArchivePath: "aplane-backup-20261120T101010.000000000Z.tar.gz",
		Error:       strings.Repeat("restore committed but runtime reload failed; signing is blocked pending recovery ", 4),
	}
	for i := range 12 {
		result.Skipped = append(result.Skipped, RestoreSkipped{Selector: fmt.Sprintf("SKIPPED%051d", i), Reason: longSkipReason})
	}
	m := sizedForTest(t, Model{viewState: ViewRestoreDisplay, restore: restoreState{result: result}}, MinWidth, MinHeight)
	for step := range 12 {
		view := fitsMinSizeForTest(t, m)
		for _, want := range []string{"╚", "Total: 0 activated keys, 12 skipped", "> SKIPPED", "runtime reload failed"} {
			if !strings.Contains(view, want) {
				t.Fatalf("cursor at row %d: %q missing from:\n%s", step, want, view)
			}
		}
		m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
}

// A recovery refusal naming a store path, a word wider than the popup, is
// counted as the lines it takes: with two restored keys and twelve skipped
// ones the border, the total and the cursor's row stay on screen at the
// minimum size, wherever the cursor is.
func TestRestoreResultWithAWideWordInTheErrorFitsAtMinSize(t *testing.T) {
	path := "/var/lib/aplane-with-a-longer-data-directory/identities/default/generations/gen-1795194116-395d2716/keys/" +
		"Q7FNSKXZ3B5O6XWIWNSXJ7AE3PJ4UIBMOJGRULNRNNDX4UDDC6RMCVXEXY.key"
	result := RestoreDisplayResult{
		ArchivePath: "aplane-backup.tar.gz",
		Error: "recovery restore refused because destination authority outside the authenticated credential selection is damaged: " +
			"unselected credentials: Failed to read key file " + path + ": key file must be encrypted",
		Activated: []RestoreKeyInfo{{Address: "GOODADDR1", KeyType: "ed25519"}, {Address: "GOODADDR2", KeyType: "ed25519"}},
	}
	for i := range 12 {
		result.Skipped = append(result.Skipped, RestoreSkipped{Selector: fmt.Sprintf("SKIPPED%051d", i), Reason: longSkipReason})
	}
	m := sizedForTest(t, Model{viewState: ViewRestoreDisplay, restore: restoreState{result: result}}, MinWidth, MinHeight)
	for step := range result.rowCount() {
		view := fitsMinSizeForTest(t, m)
		for _, want := range []string{"╚", "Total: 2 activated keys, 12 skipped", "> "} {
			if !strings.Contains(view, want) {
				t.Fatalf("cursor at row %d: %q missing from:\n%s", step, want, view)
			}
		}
		m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
}

// A restore that lists only some of the keys it restored, or of the
// conflicts it refused for, counts them all.
func TestRestoreScreensCountWhatTheyDoNotList(t *testing.T) {
	m := Model{viewState: ViewRestoring, restore: restoreState{archivePath: "aplane-backup.tar.gz"}}
	refused := updateModel(t, m, RestoreBackupResultMsg{Result: protocol.RestoreBackupResultMessage{
		Code: protocol.ResultCodeRestoreConflict, Conflicts: []protocol.RestoreConflict{{Selector: "CONFLICTADDR", KeyType: "ed25519"}}, ConflictsOmitted: 9,
	}})
	if !strings.Contains(refused.restore.passphraseError, "10 credential conflict(s)") {
		t.Fatalf("conflict prompt = %q", refused.restore.passphraseError)
	}
	if view := squeezeForTest(stripANSI(refused.renderRestorePassphrase())); !strings.Contains(view, "CONFLICTADDR [ed25519] and 9 more") {
		t.Fatalf("the replacement confirmation does not count every conflict:\n%s", view)
	}
	done := updateModel(t, m, RestoreBackupResultMsg{Result: protocol.RestoreBackupResultMessage{
		Success: true, Restored: []protocol.RestoreCredential{{Selector: "GOODADDR", KeyType: "ed25519"}}, RestoredOmitted: 70,
	}})
	view := squeezeForTest(fitsMinSizeForTest(t, done))
	for _, want := range []string{"Activated: 71 (1 listed)", "Total: 71 activated keys"} {
		if !strings.Contains(view, want) {
			t.Fatalf("%q missing from:\n%s", want, view)
		}
	}
}
