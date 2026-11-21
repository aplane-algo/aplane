// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// A long error is cut in the middle, not at its end, where a Go error names
// its cause: the operator still reads that the disk is full.
func TestErrorCutKeepsItsCause(t *testing.T) {
	const cause = "no space left on device"
	text := "Error: backup export failed: open /home/operator-with-a-long-name/.local/share/aplane/apsigner-data/" +
		"identities/default/backups/exports/2026-11-21T04-28-41Z-signer-backup-archive.apbackup.tmp: " + cause
	lines := wrapCutLines(text, MinWidth, maxErrorLines)
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

// wrapCutLines returns at any width, a character wider than the width
// included, and keeps the error's end.
func TestWrapErrorLinesEndsForAWideCharacter(t *testing.T) {
	for _, width := range []int{0, 1, 2} {
		done := make(chan []string, 1)
		go func() { done <- wrapCutLines("Error: 漢字のパス", width, maxErrorLines) }()
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
			t.Fatalf("width %d: wrapCutLines does not return", width)
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

// ellipsizeMiddle keeps a string's start and end in columns as the terminal
// draws them, a two-column character cut at the middle included.
func TestEllipsizeMiddleCountsColumns(t *testing.T) {
	for _, tc := range []struct {
		in    string
		width int
		want  string
	}{
		{"漢字漢字漢字", 12, "漢字漢字漢字"},
		{"漢字のパス漢字", 9, "漢...字"},
		{"ab漢字のパスcd", 10, "ab...スcd"},
		{"ab漢字のパスcd", 11, "ab漢...スcd"},
		{"漢字漢字漢字", 3, "漢"},
		{"SGCU7MLRXQ4H227YCRTTT6MHL2N64WGJ", 13, "SGCU7...64WGJ"},
	} {
		if got := ellipsizeMiddle(tc.in, tc.width); got != tc.want || lipgloss.Width(got) > tc.width {
			t.Errorf("ellipsizeMiddle(%q, %d) = %q (%d columns), want %q", tc.in, tc.width, got, lipgloss.Width(got), tc.want)
		}
	}
}

// wrapPlainText fills lines to columns as the terminal draws them: a line of
// two-column words wraps neither early nor past its width.
func TestWrapPlainTextCountsColumns(t *testing.T) {
	got := wrapPlainText("漢字 漢字 漢字 漢字", 9)
	if got != "漢字 漢字\n漢字 漢字" {
		t.Fatalf("wrapped to %q", got)
	}
	for _, line := range strings.Split(wrapPlainText(strings.Repeat("パス ", 30), 20), "\n") {
		if lipgloss.Width(line) > 20 {
			t.Errorf("line %q is %d columns", line, lipgloss.Width(line))
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

// checkBodyFits fails when m's screen needs more rows than the window body
// under the status bar as drawn has, so the window would cut it.
func checkBodyFits(t *testing.T, name string, m Model) {
	t.Helper()
	content := strings.TrimRight(stripANSI(m.renderViewContent()), "\n")
	if need := strings.Count(content, "\n") + 1; need > m.windowBodyHeight() {
		t.Errorf("%s: needs %d rows, the body has %d, so the window cuts it:\n%s", name, need, m.windowBodyHeight(), stripANSI(m.View()))
	}
}

// Every text pager measures its height under the status bar as drawn, so a
// long error takes its rows from the text: the end of the text and the
// marker for the lines below stay on screen, as does what the pager draws
// under the text.
func TestTextPagersFollowAWrappedStatusBar(t *testing.T) {
	const total = 40
	lines := make([]string, total)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%03d", i)
	}
	for _, p := range textPagers() {
		for _, standalone := range []bool{false, true} {
			name := fmt.Sprintf("%s standalone %v", p.name, standalone)
			m := sizedForTest(t, Model{standalone: standalone, connectionState: ConnectionConnected}, MinWidth, MinHeight)
			p.setup(&m, lines)
			m.lastError = longDaemonError
			checkBodyFits(t, name, m)
			if _, _, _, below := shownLines(t, stripANSI(m.View())); !below {
				t.Errorf("%s: no marker for the lines below:\n%s", name, stripANSI(m.View()))
			}
			for range total {
				m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyPgDown})
			}
			view := stripANSI(m.View())
			checkFitsMinSize(t, view)
			checkBodyFits(t, name, m)
			if _, last, _, _ := shownLines(t, view); last != total-1 {
				t.Errorf("%s: scrolled to the end, the last line shown is %d:\n%s", name, last, view)
			}
			if p.name == "policy apply review" && !strings.Contains(strings.Join(strings.Fields(view), " "), "activates them immediately. y: Apply") {
				t.Errorf("%s: the prompt or its footer is cut:\n%s", name, view)
			}
		}
	}
}

// The admin panel scrolls its settings around the selected one when they do
// not fit, as they do not with a long error or standalone, so the last
// settings are not cut off without a marker.
func TestAdminPanelScrollsUnderAWrappedStatusBar(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		m := sizedForTest(t, Model{viewState: ViewAdminPanel, standalone: standalone, connectionState: ConnectionConnected, lastError: longDaemonError,
			admin: adminPanelState{editingRow: -1, settings: &AdminSettings{PassphraseMethod: "none", Theme: "auto"}}}, MinWidth, MinHeight)
		name := fmt.Sprintf("standalone %v", standalone)
		view := stripANSI(m.View())
		checkFitsMinSize(t, view)
		checkBodyFits(t, name, m)
		if !strings.Contains(view, "> User Auto-Approve") || !strings.Contains(view, "▼") {
			t.Errorf("%s: the first setting or the marker below it is not on screen:\n%s", name, view)
		}
		m.admin.selectedRow = len(m.adminRows()) - 1
		view = stripANSI(m.View())
		checkBodyFits(t, name, m)
		if !strings.Contains(view, "> Build") || !strings.Contains(view, "▲") {
			t.Errorf("%s: the last setting or the marker above it is not on screen:\n%s", name, view)
		}
	}
}

// The KeyType Library and the policy editor size themselves from the window
// body under the status bar as drawn.
func TestLibraryAndPolicyEditorFollowAWrappedStatusBar(t *testing.T) {
	var entries []protocol.LibraryTemplateInfo
	for i := range 30 {
		entries = append(entries, protocol.LibraryTemplateInfo{KeyType: fmt.Sprintf("example.t%02d.v1", i), TemplateType: "generic",
			DisplayName: "Template", Description: "a template", FileName: "template.yaml"})
	}
	for _, standalone := range []bool{false, true} {
		for _, errText := range []string{"", longDaemonError} {
			name := fmt.Sprintf("standalone %v error %v", standalone, errText != "")
			lib := sizedForTest(t, Model{viewState: ViewTemplateLibrary, standalone: standalone, connectionState: ConnectionConnected,
				lastError: errText, library: libraryState{templates: entries}}, MinWidth, MinHeight)
			checkBodyFits(t, "library "+name, lib)
			if view := stripANSI(lib.View()); !strings.Contains(view, "File:") || !strings.Contains(view, "▼") {
				t.Errorf("library %s: the entry's details or the marker below the list is cut:\n%s", name, view)
			}

			ed := cosignerPoliciesModel("default")
			ed.standalone = standalone
			ed = sizedForTest(t, ed, MinWidth, MinHeight)
			ed = openEditorForKeyOnDefault(t, ed)
			ed.lastError = errText
			ed.policies.apply.err = "the check refused the document"
			checkBodyFits(t, "editor "+name, ed)
			if view := stripANSI(ed.View()); !strings.Contains(view, "the check refused the document") {
				t.Errorf("editor %s: the message under the text is cut:\n%s", name, view)
			}
		}
	}
}

// A failed cosigner list is shown once on the manager, in the manager's own
// block, not again in the status bar, so the manager keeps the rows for the
// selected row and the whole path of the file remove does not reach. On
// another screen the status bar still reports it.
func TestFailedCosignerListShowsOnceOnTheManager(t *testing.T) {
	const deep = "/home/operator-with-a-long-name/.local/share/aplane/apsigner-data/identities/default/cosigners/nested/deeper/still-deeper/"
	const name = "copy of the west cosigner reference from the old machine before the move"
	for _, standalone := range []bool{false, true} {
		m := fullInvalidCosignerReferencesModel(t, deep, name, standalone)
		m = press(t, m, "enter")
		m.cosigner.managerStatus = "Removed bad"
		m = updateModel(t, m, CosignerReferencesMsg{Error: veryLongDaemonError})
		view := stripANSI(m.View())
		checkFitsMinSize(t, view)
		checkBodyFits(t, fmt.Sprintf("standalone %v", standalone), m)
		flat := strings.Join(strings.Fields(view), "")
		if !strings.Contains(flat, strings.Join(strings.Fields(deep+name+".json"), "")) || !strings.Contains(view, "> copy of") {
			t.Errorf("standalone %v: the file's path or the selected row is cut:\n%s", standalone, view)
		}
		if got := strings.Count(view, "the store is full"); got != 1 {
			t.Errorf("standalone %v: the list error is on screen %d times:\n%s", standalone, got, view)
			t.Log(stripANSI(m.renderStatusBar()))
		}

		// Left on the key list, the failure is in the status bar, and the
		// manager opened after it shows it once.
		m = press(t, m, "esc")
		if view := stripANSI(m.View()); !strings.Contains(view, "Error: the signer refused") {
			t.Errorf("standalone %v: the key list does not report the failed list:\n%s", standalone, view)
		}
		m = press(t, m, "e")
		if view := stripANSI(m.View()); m.viewState != ViewCosignerReferences || strings.Count(view, "the store is full") != 1 {
			t.Errorf("standalone %v: the reopened manager shows the error %d times:\n%s", standalone, strings.Count(view, "the store is full"), view)
		}
	}
}

// A list at its top or bottom shows a row where the marker it does not need
// would be, so no screen keeps an empty row for it: in the middle the list
// shows a row fewer than at either end.
func TestListWindowShowsARowForAMarkerItDoesNotNeed(t *testing.T) {
	var keys []protocol.PolicyKeyStatusWire
	for i := range 30 {
		keys = append(keys, protocol.PolicyKeyStatusWire{Key: fmt.Sprintf("P%057d", i), Status: adminproto.PolicyKeyOwn})
	}
	shown := func(selected int) (rows int, above, below bool) {
		m := sizedForTest(t, Model{viewState: ViewPolicies, policies: policiesState{selected: selected,
			policy: protocol.PolicyMessage{NodeRole: "signer", Keys: keys, PolicySetSHA256: strings.Repeat("ab", 32)}}}, MinWidth, MinHeight)
		view := stripANSI(m.View())
		return strings.Count(view, "  P0") + strings.Count(view, "> P0"), strings.Contains(view, "▲"), strings.Contains(view, "▼")
	}
	middle, _, _ := shown(15)
	if rows, above, below := shown(0); rows != middle+1 || above || !below {
		t.Errorf("at the top: %d rows (middle %d), above %v, below %v", rows, middle, above, below)
	}
	if rows, above, below := shown(29); rows != middle+1 || !above || below {
		t.Errorf("at the bottom: %d rows (middle %d), above %v, below %v", rows, middle, above, below)
	}

	// Standalone the settings scroll; in a pane they all fit. The gap under
	// the title is the same either way.
	gap := func(standalone bool) int {
		m := sizedForTest(t, Model{viewState: ViewAdminPanel, standalone: standalone, connectionState: ConnectionConnected,
			admin: adminPanelState{editingRow: -1, settings: &AdminSettings{PassphraseMethod: "none", Theme: "auto"}}}, MinWidth, MinHeight)
		view := stripANSI(m.View())
		if scrolls := strings.Contains(view, "▼"); scrolls != standalone {
			t.Fatalf("standalone %v: the settings scroll: %v:\n%s", standalone, scrolls, view)
		}
		title, first := -1, -1
		for i, line := range strings.Split(view, "\n") {
			switch strings.TrimSpace(line) {
			case "Settings":
				title = i
			case "User-Editable":
				first = i
			}
		}
		return first - title
	}
	if pane, standalone := gap(false), gap(true); standalone != pane {
		t.Errorf("the settings start %d rows under the title when they scroll, %d when they fit", standalone, pane)
	}
}

// Every status bar part fits the window, not only the error: a part too long
// for the line goes under it, wrapped and cut in the middle, and the rows
// under the line, at most maxErrorLines, go to the alert, then the error,
// then the warning, then the notice, a row kept for each while rows last.
func TestStatusBarFitsEveryPartByRank(t *testing.T) {
	long := func(what, end string) string {
		return what + " " + strings.Repeat("with a reason long enough to need more than a line ", 3) + end
	}
	bar := func(m Model) []string {
		t.Helper()
		m = sizedForTest(t, m, MinWidth, MinHeight)
		lines := strings.Split(stripANSI(m.renderStatusBar()), "\n")
		if len(lines) > 1+maxErrorLines {
			t.Errorf("a status bar of %d lines:\n%s", len(lines), strings.Join(lines, "\n"))
		}
		for _, line := range lines {
			if lipgloss.Width(line) > MinWidth {
				t.Errorf("line wider than the window: %q", line)
			}
		}
		return lines
	}
	base := Model{viewState: ViewKeyList, connectionState: ConnectionConnected, signerStatusKnown: true, signerState: signerRuntimeUnlocked}

	all := base
	all.signerWarnings = []string{long("the store root failed its check", "ALERT-END")}
	all.lastError = long("the signer refused the request", "ERROR-END")
	all.lastWarning = long("the policy sidecar is stale", "WARNING-END")
	all.lastNotice = long("copied the address", "NOTICE-END")
	lines := bar(all)
	joined := strings.Join(lines, "\n")
	if len(lines) != 1+maxErrorLines || !strings.HasPrefix(lines[1], "ALERT: the store root") || !strings.HasSuffix(strings.TrimRight(lines[1], " "), "ALERT-END") ||
		!strings.Contains(joined, "WARNING-END") || !strings.HasSuffix(strings.TrimRight(lines[3], " "), "ERROR-END") || strings.Contains(joined, "NOTICE-END") ||
		!strings.HasSuffix(strings.TrimRight(lines[0], " "), "| +1 more: notice") {
		t.Errorf("four long parts in three rows: one row each for the alert, the warning and the error, and the notice counted:\n%s", joined)
	}

	two := base
	two.lastWarning = long("the policy sidecar is stale", "WARNING-END")
	two.lastNotice = long("copied the address", "NOTICE-END")
	lines = bar(two)
	if len(lines) != 4 || !strings.HasPrefix(lines[1], "copied the address") || !strings.HasSuffix(strings.TrimRight(lines[1], " "), "NOTICE-END") ||
		!strings.HasPrefix(lines[2], "Warning: the policy") || !strings.HasSuffix(strings.TrimRight(lines[3], " "), "WARNING-END") {
		t.Errorf("the warning gets two rows and the notice one, shown in the line's order:\n%s", strings.Join(lines, "\n"))
	}

	short := base
	short.lastNotice = "Copied"
	short.lastError = long("the signer refused the request", "ERROR-END")
	lines = bar(short)
	if !strings.HasSuffix(strings.TrimRight(lines[0], " "), "| Copied") || !strings.HasPrefix(lines[1], "Error: the signer refused") {
		t.Errorf("a short notice stays on the line when a long error goes under it:\n%s", strings.Join(lines, "\n"))
	}
}

// A failed backup list is shown once on the Backups page, in the page's own
// header, not again in the status bar; on another screen the bar reports it.
func TestFailedBackupListShowsOnceOnTheBackupsPage(t *testing.T) {
	const cause = "open /var/lib/aplane/apsigner-data/identities/default/backups: permission denied"
	for _, standalone := range []bool{false, true} {
		m := backupsModel(BackupInfo{FileName: "lab-signer.tar.gz", Size: 100})
		m.standalone, m.connectionState = standalone, ConnectionConnected
		m = sizedForTest(t, m, MinWidth, MinHeight)
		m = updateModel(t, m, BackupsListMsg{Error: cause})
		view := stripANSI(m.View())
		checkFitsMinSize(t, view)
		if got := strings.Count(view, "denied"); got != 1 {
			t.Errorf("standalone %v: the list error is on screen %d times:\n%s", standalone, got, view)
		}
		m = press(t, m, "esc")
		if view := stripANSI(m.View()); m.viewState != ViewKeyList || !strings.Contains(view, "Error: Backup list failed: open") {
			t.Errorf("standalone %v: the key list does not report the failed list:\n%s", standalone, view)
		}
	}
}

// The status bar never leaves a part out without saying so, and never the
// error: lost notifications, which can be a missed approval, rank with the
// signer's alerts, the error keeps a row however many alerts there are, and
// a count on the line names what does not fit.
func TestStatusBarCountsWhatItLeavesOut(t *testing.T) {
	alert := func(i int) string {
		return fmt.Sprintf("policy %d names network testnet-%d, which this node does not know; the document keeps working", i, i)
	}
	for _, tc := range []struct {
		name   string
		alerts []string
		conn   ConnectionState
		state  signerRuntimeState
		count  string
	}{
		{"a short alert and two long ones", []string{"store health: archive member bad", alert(1), alert(2)},
			ConnectionConnected, signerRuntimeUnlocked, "| +4 more: alert, warning, notice"},
		{"disconnected and in recovery with two alerts", []string{alert(0), alert(1)},
			ConnectionDisconnected, signerRuntimeRecovery, "| +3"},
		{"three long alerts", []string{alert(0), alert(1), alert(2)},
			ConnectionConnected, signerRuntimeUnlocked, "| +4 more: alert, warning, notice"},
		{"five alerts", []string{alert(0), alert(1), alert(2), alert(3), alert(4)},
			ConnectionConnected, signerRuntimeUnlocked, "| +6 more: alert, warning, notice"},
	} {
		m := sizedForTest(t, Model{viewState: ViewKeyList, connectionState: tc.conn, signerStatusKnown: true, signerState: tc.state, keyCount: 123,
			signerWarnings: tc.alerts, notificationsLost: 2, lastError: longDaemonError, lastWarning: "the policy was applied but its sidecar is stale",
			lastNotice: "Copied the address to the clipboard"}, MinWidth, MinHeight)
		lines := strings.Split(stripANSI(m.renderStatusBar()), "\n")
		bar := strings.Join(lines, "\n")
		if len(lines) != 1+maxErrorLines || !strings.HasSuffix(strings.TrimRight(lines[0], " "), tc.count) ||
			!strings.Contains(bar, "Warning: 2 signer notifications lost") || !strings.Contains(bar, "ALERT: ") ||
			!strings.HasSuffix(strings.TrimRight(lines[len(lines)-1], " "), "permission denied") {
			t.Errorf("%s: want the lost notifications, an alert, the error, and %q on the line:\n%s", tc.name, tc.count, bar)
		}
		for _, line := range lines {
			if lipgloss.Width(line) > MinWidth {
				t.Errorf("%s: line wider than the window: %q", tc.name, line)
			}
		}
	}
}
