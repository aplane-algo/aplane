// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// A long error is cut in the middle, not at its end, where a Go error names
// its cause: the operator still reads that the disk is full.
func TestErrorCutKeepsItsCause(t *testing.T) {
	const cause = "no space left on device"
	text := "Error: backup export failed: open /home/operator-with-a-long-name/.local/share/aplane/apsigner-data/" +
		"identities/default/backups/exports/2026-11-21T04-28-41Z-signer-backup-archive.apbackup.tmp: " + cause
	lines := wrapErrorLines(text, MinWidth)
	if len(lines) != maxErrorLines || lines[0] != "Error: backup export failed: open" ||
		!strings.HasSuffix(lines[len(lines)-2], "...") || lines[len(lines)-1] != cause {
		t.Fatalf("cut to:\n%s", strings.Join(lines, "\n"))
	}
	for _, line := range lines {
		if lipgloss.Width(line) > MinWidth {
			t.Errorf("line wider than %d: %q", MinWidth, line)
		}
	}

	m := sizedForTest(t, Model{viewState: ViewKeyList, connectionState: ConnectionConnected,
		lastError: strings.TrimPrefix(text, "Error: ")}, MinWidth, MinHeight)
	view := strings.Split(strings.TrimRight(stripANSI(m.View()), "\n"), "\n")
	if last := strings.TrimRight(view[len(view)-1], " "); last != cause {
		t.Fatalf("the screen ends with %q, not the cause:\n%s", last, strings.Join(view, "\n"))
	}
}

// wrapErrorLines returns at any width, a character wider than the width
// included, and keeps the error's end.
func TestWrapErrorLinesEndsForAWideCharacter(t *testing.T) {
	for _, width := range []int{0, 1, 2} {
		done := make(chan []string, 1)
		go func() { done <- wrapErrorLines("Error: 漢字のパス", width) }()
		select {
		case lines := <-done:
			if len(lines) > maxErrorLines || lines[len(lines)-1] != "ス" {
				t.Errorf("width %d: %q", width, lines)
			}
			for _, line := range lines {
				// A two-column character is wider than a one-column line.
				if lipgloss.Width(line) > max(width, 2) {
					t.Errorf("width %d: line %q is %d columns", width, line, lipgloss.Width(line))
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("width %d: wrapErrorLines does not return", width)
		}
	}
}

// ellipsize cuts to columns as the terminal draws them, so a line of
// two-column characters stays inside its width.
func TestEllipsizeCountsColumns(t *testing.T) {
	for _, tc := range []struct {
		in    string
		width int
		want  string
	}{
		{"漢字漢字漢字", 12, "漢字漢字漢字"},
		{"漢字漢字漢字", 9, "漢字漢..."},
		{"漢字漢字漢字", 8, "漢字..."},
		{"漢字漢字漢字", 3, "漢"},
		{"plain text here", 10, "plain t..."},
		{"plain", 3, "pla"},
	} {
		if got := ellipsize(tc.in, tc.width); got != tc.want || lipgloss.Width(got) > tc.width {
			t.Errorf("ellipsize(%q, %d) = %q (%d columns), want %q", tc.in, tc.width, got, lipgloss.Width(got), tc.want)
		}
	}
}

// A setting update's warning is measured against the status line as it is
// drawn: an error that goes under the line leaves the line its room.
func TestSettingWarningShowsBesideAnErrorUnderTheLine(t *testing.T) {
	m := sizedForTest(t, Model{viewState: ViewAdminPanel, connectionState: ConnectionConnected, lastError: longDaemonError,
		admin: adminPanelState{editingRow: -1, settings: &AdminSettings{PassphraseMethod: "none", Theme: "auto"},
			settingWarning: settingResultWarning{key: "theme", text: "theme is in effect but not saved"}}}, MinWidth, MinHeight)
	bar := strings.Split(stripANSI(m.renderStatusBar()), "\n")
	if len(bar) < 2 || !strings.Contains(bar[0], "theme is in effect but not saved") || !strings.HasPrefix(bar[1], "Error: ") {
		t.Fatalf("status bar:\n%s", strings.Join(bar, "\n"))
	}
	checkFitsMinSize(t, stripANSI(m.View()))
}

// scrolledKeyListModel is the key list at the minimum size holding count
// keys, scrolled to the last, which is selected.
func scrolledKeyListModel(t *testing.T, count int, standalone bool) (Model, string) {
	t.Helper()
	var keys []KeyInfo
	for i := range count {
		keys = append(keys, KeyInfo{Address: fmt.Sprintf("K%02dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", i), KeyType: "ed25519"})
	}
	m := sizedForTest(t, Model{viewState: ViewKeyList, standalone: standalone, connectionState: ConnectionConnected,
		signerState: signerRuntimeUnlocked, signerStatusKnown: true, keylist: keyListState{keys: keys}}, MinWidth, MinHeight)
	for range count - 1 {
		m = press(t, m, "down")
	}
	return m, "> " + keys[count-1].Address[:10]
}

// An error that arrives after the operator scrolled a list takes rows from
// it, and the selected row stays on screen: enter and d act on the row the
// operator sees.
func TestALongErrorKeepsTheSelectedRowOnScreen(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		m, selected := scrolledKeyListModel(t, 40, standalone)
		before := m.keyListVisibleHeight()
		m = updateModel(t, m, ErrorMsg{Error: errors.New(longDaemonError)})
		if m.keyListVisibleHeight() >= before {
			t.Fatalf("standalone %v: the error takes no rows from the key list", standalone)
		}
		view := stripANSI(m.View())
		checkFitsMinSize(t, view)
		if !strings.Contains(view, selected) {
			t.Errorf("standalone %v: the selected key %q is not on screen:\n%s", standalone, selected, view)
		}
		if view := stripANSI(press(t, m, "up").View()); !strings.Contains(view, "> K38") {
			t.Errorf("standalone %v: up does not move to the row above:\n%s", standalone, view)
		}

		var entries []protocol.LibraryTemplateInfo
		for i := range 30 {
			entries = append(entries, protocol.LibraryTemplateInfo{KeyType: fmt.Sprintf("example.t%02d.v1", i), TemplateType: "generic"})
		}
		lib := sizedForTest(t, Model{viewState: ViewTemplateLibrary, standalone: standalone, connectionState: ConnectionConnected,
			library: libraryState{templates: entries}}, MinWidth, MinHeight)
		for range len(entries) - 1 {
			lib = press(t, lib, "down")
		}
		lib = updateModel(t, lib, ErrorMsg{Error: errors.New(longDaemonError)})
		view = stripANSI(lib.View())
		checkFitsMinSize(t, view)
		if !strings.Contains(view, "> example.t29.v1") {
			t.Errorf("standalone %v: the selected library entry is not on screen:\n%s", standalone, view)
		}
	}
}
