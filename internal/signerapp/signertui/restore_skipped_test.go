// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

// A preview whose archive holds a key the node cannot admit shows it as an
// error row and again under the warnings, never selected; the keys it can
// restore are preselected.
func TestRestorePreviewShowsAnInadmissibleKey(t *testing.T) {
	m := Model{
		viewState: ViewRestorePassphrase,
		restore:   restoreState{archivePath: "aplane-backup.tar.gz", passphrase: []byte("export-passphrase"), previewing: true, pendingID: "preview-1"},
	}
	m = updateModel(t, m, RestorePreviewMsg{
		ID: "preview-1", ArchivePath: "aplane-backup.tar.gz",
		Keys: []RestoreKeyInfo{
			{Address: "GOODADDR", KeyType: "ed25519"},
			{Address: "BADADDR", Error: "failed to parse backup credential"},
		},
		Errors: []RestoreError{{Address: "BADADDR", Error: "failed to parse backup credential"}},
	})
	if m.viewState != ViewRestorePreview {
		t.Fatalf("viewState = %v, want ViewRestorePreview", m.viewState)
	}
	if got := m.selectedRestoreAddresses(); len(got) != 1 || got[0] != "GOODADDR" {
		t.Fatalf("selected = %q, want only GOODADDR", got)
	}
	m.restore.selectedKey = 1
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")})
	if m.restore.selected["BADADDR"] {
		t.Fatal("the inadmissible key became selectable")
	}
	view := fitsMinSizeForTest(t, m)
	for _, want := range []string{"Selected: 1 of 2", "BADADDR", "failed to parse", "Preview warnings:", "BADADDR: failed to parse backup credential"} {
		if !strings.Contains(view, want) {
			t.Fatalf("%q missing from:\n%s", want, view)
		}
	}
}

// The result screen lists the keys the restore activated.
func TestRestoreResultListsActivatedKeys(t *testing.T) {
	m := Model{
		viewState: ViewRestoreDisplay,
		restore: restoreState{result: RestoreDisplayResult{
			ArchivePath: "aplane-backup.tar.gz", Success: true,
			Activated: []RestoreKeyInfo{{Address: "GOODADDR", KeyType: "ed25519", HasPolicy: true}},
		}},
	}
	view := fitsMinSizeForTest(t, m)
	for _, want := range []string{"Restore Complete", "Archive: aplane-backup.tar.gz", "Activated: 1", "Restored keys:", "GOODADDR  [ed25519]  policy", "Total: 1 activated keys"} {
		if !strings.Contains(view, want) {
			t.Fatalf("%q missing from:\n%s", want, view)
		}
	}
}
