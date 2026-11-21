// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// longErrorScreen is one screen of the long-error sweep: build draws it at
// the minimum size, and selected is text on its selected row, "" when it has
// none.
type longErrorScreen struct {
	name     string
	build    func(t *testing.T, standalone bool) Model
	selected string
}

// populatedLongErrorScreens are the screens whose content outgrows the
// window, each with its selection, where it has one, at the far end.
func populatedLongErrorScreens() []longErrorScreen {
	lines := make([]string, 40)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%03d", i)
	}
	pageToEnd := func(t *testing.T, m Model) Model {
		for range len(lines) {
			m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyPgDown})
		}
		return m
	}
	screens := []longErrorScreen{
		{"key list", func(t *testing.T, standalone bool) Model {
			m, _ := scrolledKeyListModel(t, 40, standalone)
			return m
		}, "K39AAAAAAA"},
		{"KeyType Library", func(t *testing.T, standalone bool) Model {
			var entries []protocol.LibraryTemplateInfo
			for i := range 30 {
				entries = append(entries, protocol.LibraryTemplateInfo{KeyType: fmt.Sprintf("example.t%02d.v1", i), TemplateType: "generic",
					DisplayName: "Template", Description: "a template", FileName: "template.yaml"})
			}
			m := sizedForTest(t, Model{viewState: ViewTemplateLibrary, standalone: standalone, library: libraryState{templates: entries}}, MinWidth, MinHeight)
			return press(t, m, slicesRepeat("down", len(entries)-1)...)
		}, "example.t29.v1"},
		{"cosigner manager", func(t *testing.T, standalone bool) Model {
			return fullInvalidCosignerReferencesModel(t, "/var/lib/aplane/cosigners/", "last-file", standalone)
		}, "last-file.json"},
		{"policies", func(t *testing.T, standalone bool) Model {
			var keys []protocol.PolicyKeyStatusWire
			for i := range 30 {
				keys = append(keys, protocol.PolicyKeyStatusWire{Key: fmt.Sprintf("P%057d", i), Status: adminproto.PolicyKeyOwn})
			}
			return sizedForTest(t, Model{viewState: ViewPolicies, standalone: standalone, policies: policiesState{selected: 29,
				policy: protocol.PolicyMessage{NodeRole: "signer", Keys: keys, PolicySetSHA256: strings.Repeat("ab", 32)}}}, MinWidth, MinHeight)
		}, fmt.Sprintf("P%057d", 29)},
		{"enrolled clients", func(t *testing.T, standalone bool) Model {
			var keys []protocol.EnrolledKeyInfo
			for i := range 30 {
				keys = append(keys, protocol.EnrolledKeyInfo{Fingerprint: fmt.Sprintf("SHA256:%043d", i), Label: fmt.Sprintf("client-%02d", i), KeyType: "ssh-ed25519"})
			}
			return sizedForTest(t, Model{viewState: ViewEnrolledClients, standalone: standalone, clients: clientsState{keys: keys, selected: 29}}, MinWidth, MinHeight)
		}, fmt.Sprintf("SHA256:%043d", 29)},
		{"backups", func(t *testing.T, standalone bool) Model {
			var backups []BackupInfo
			for i := range 30 {
				backups = append(backups, BackupInfo{FileName: fmt.Sprintf("backup-%02d.tar.gz", i), Size: 72000})
			}
			m := backupsModel(backups...)
			m.standalone, m.restore.selectedBackup = standalone, 29
			return sizedForTest(t, m, MinWidth, MinHeight)
		}, "backup-29.tar.gz"},
		{"restore preview", func(t *testing.T, standalone bool) Model {
			var keys []RestoreKeyInfo
			selected := map[string]bool{}
			for i := range 30 {
				address := fmt.Sprintf("R%02d%055d", i, 0)
				keys = append(keys, RestoreKeyInfo{Address: address, KeyType: "ed25519"})
				selected[address] = true
			}
			m := sizedForTest(t, Model{viewState: ViewRestorePreview, standalone: standalone, restore: restoreState{
				archivePath: "/backups/backup.tar.gz", previewKeys: keys, selected: selected}}, MinWidth, MinHeight)
			for range len(keys) - 1 {
				m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
			}
			return m
		}, "R29"},
		{"restore result", func(t *testing.T, standalone bool) Model {
			var keys []RestoreKeyInfo
			for i := range 30 {
				keys = append(keys, RestoreKeyInfo{Address: fmt.Sprintf("RESTOREDADDR%02d", i), KeyType: "ed25519"})
			}
			m := sizedForTest(t, Model{viewState: ViewRestoreDisplay, standalone: standalone, restore: restoreState{result: RestoreDisplayResult{
				ArchivePath: "/backups/backup.tar.gz", Activated: keys, Success: true}}}, MinWidth, MinHeight)
			for range len(keys) - 1 {
				m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
			}
			return m
		}, "RESTOREDADDR29"},
		{"generate form", func(t *testing.T, standalone bool) Model {
			manyServerKeyTypes(t, 20)
			m := sizedForTest(t, Model{viewState: ViewGenerateForm, standalone: standalone}, MinWidth, MinHeight)
			for range 19 {
				m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
			}
			return m
		}, "test.keytype-19.v1"},
		{"admin panel", func(t *testing.T, standalone bool) Model {
			m := sizedForTest(t, Model{viewState: ViewAdminPanel, standalone: standalone,
				admin: adminPanelState{editingRow: -1, settings: &AdminSettings{PassphraseMethod: "none", Theme: "auto", NodeRole: "signer"}}}, MinWidth, MinHeight)
			m.admin.selectedRow = len(m.adminRows()) - 1
			return m
		}, "Build"},
		{"approval review", func(t *testing.T, standalone bool) Model {
			return reviewModelForTest(t, payrollReviewRequest(10), standalone, MinWidth, MinHeight)
		}, "REJECT (n)"},
		{"group approval review", func(t *testing.T, standalone bool) Model {
			return reviewModelForTest(t, groupReviewRequest(), standalone, MinWidth, MinHeight)
		}, "REJECT (n)"},
		{"policy editor", func(t *testing.T, standalone bool) Model {
			m := cosignerPoliciesModel("default")
			m.standalone = standalone
			m = openEditorForKeyOnDefault(t, sizedForTest(t, m, MinWidth, MinHeight))
			m.policies.apply.err = "the check refused the document"
			return m
		}, ""},
	}
	for _, p := range textPagers() {
		screens = append(screens, longErrorScreen{p.name + " pager", func(t *testing.T, standalone bool) Model {
			m := sizedForTest(t, Model{standalone: standalone}, MinWidth, MinHeight)
			p.setup(&m, lines)
			return pageToEnd(t, m)
		}, ""})
	}
	return screens
}

func slicesRepeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// statusMessages is what the sweep puts in the status bar beside the
// screen: an error, and for the last set a long alert, notice and warning
// and lost notifications as well. ends is the end of each message the bar
// must show; the error's ends the screen.
type statusMessages struct {
	name                   string
	err                    string
	alert, notice, warning string
	lost                   uint64
	ends                   []string
}

func longErrorStatusMessages() []statusMessages {
	const address = "SGCU7MLRXQ4H227YCRTTT6MHL2N64WGJPHH3OTPID2CK4JNGJU6DITLIUQ"
	return []statusMessages{
		{name: "long error", err: longDaemonError, ends: []string{"permission denied"}},
		{name: "very long error", err: veryLongDaemonError, ends: []string{"the store is full"}},
		{name: "long alert, notice, warning and error", err: longDaemonError,
			alert:   "the store root could not be verified against the generation on disk, so signing is held: verify failed",
			notice:  "Copied the address " + address + " to the clipboard for the operator: copied",
			warning: "the policy for key " + address + " was applied but its sidecar is stale: stale sidecar",
			// The count of the warning and notice left out keeps its room on
			// the line, so the lost notifications go under it.
			lost: 2, ends: []string{"notifications lost", "verify failed", "+2 more: warning, notice", "permission denied"}},
	}
}

// set puts the messages other than the error in m's status bar.
func (s statusMessages) set(m Model) Model {
	if s.alert != "" {
		m.signerWarnings = []string{s.alert}
	}
	m.lastNotice, m.lastWarning, m.notificationsLost = s.notice, s.warning, s.lost
	return m
}

// checkLongErrorScreen fails when m, showing msgs in its status bar, has a
// line wider than the window, is taller than it, is cut by it, hides its
// selected row, does not end with its whole status bar, or leaves out the
// end of a message the bar must show, the error's last.
func checkLongErrorScreen(t *testing.T, name string, m Model, msgs statusMessages, selected string) {
	t.Helper()
	view := stripANSI(m.View())
	lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
	if len(lines) > m.height {
		t.Errorf("%s: %d lines in a %d-line window:\n%s", name, len(lines), m.height, view)
	}
	for _, line := range lines {
		if lipgloss.Width(line) > MinWidth {
			t.Errorf("%s: line wider than the window: %q", name, line)
		}
	}
	checkBodyFits(t, name, m)
	bar := strings.Split(stripANSI(m.renderStatusBar()), "\n")
	if len(bar) > 1+maxErrorLines || len(bar) > len(lines) {
		t.Fatalf("%s: a status bar of %d lines:\n%s", name, len(bar), view)
	}
	for k, row := range bar {
		if got := lines[len(lines)-len(bar)+k]; strings.TrimRight(got, " ") != strings.TrimRight(row, " ") {
			t.Errorf("%s: the screen's row %q is not the status bar's %q:\n%s", name, got, row, view)
		}
	}
	for _, end := range msgs.ends {
		if !strings.Contains(strings.Join(bar, "\n"), end) {
			t.Errorf("%s: the status bar leaves out %q:\n%s", name, end, view)
		}
	}
	if end := msgs.ends[len(msgs.ends)-1]; !strings.HasSuffix(strings.TrimRight(lines[len(lines)-1], " "), end) {
		t.Errorf("%s: the screen does not end with the error's end %q:\n%s", name, end, view)
	}
	if selected == "" {
		return
	}
	for _, line := range lines {
		if strings.Contains(line, "> ") && strings.Contains(line, selected) {
			return
		}
	}
	t.Errorf("%s: the selected row %q is not on screen:\n%s", name, selected, view)
}

// Every apadmin screen fits 80x24, standalone and in an apconsole pane, with
// an error that wraps under the status bar, one too long for its rows, and
// a long alert, notice and warning beside an error: no line is wider than
// the window, nothing is cut without a marker, the selected row is on
// screen, the whole status bar is, and the error's end, which names its
// cause, ends the screen. The empty screens are drawn as
// TestEveryViewFitsAtMinSize draws them, and the populated ones with more
// rows than the window holds, the selection at the far end.
func TestEveryScreenFitsWithALongError(t *testing.T) {
	for _, msgs := range longErrorStatusMessages() {
		for _, standalone := range []bool{false, true} {
			for v := ViewAuth; v <= ViewStoreRecovery; v++ {
				if v == ViewPolicyEdit {
					continue // only exists with a loaded document; drawn below
				}
				m := sizedForTest(t, Model{viewState: v, standalone: standalone, auth: authState{passphraseMasked: true},
					forms: formsState{importMnemonicInput: newImportMnemonicInput()}, connectionState: ConnectionConnected,
					signerStatusKnown: true, signerState: signerRuntimeUnlocked}, MinWidth, MinHeight)
				m = msgs.set(m)
				m.lastError = msgs.err
				checkLongErrorScreen(t, fmt.Sprintf("view %d standalone %v %s", v, standalone, msgs.name), m, msgs, "")
			}
			for _, screen := range populatedLongErrorScreens() {
				m := screen.build(t, standalone)
				m.connectionState, m.signerStatusKnown, m.signerState = ConnectionConnected, true, signerRuntimeUnlocked
				m = msgs.set(m)
				// As a daemon error arrives, after the screen was drawn.
				m = updateModel(t, m, ErrorMsg{Error: errors.New(msgs.err)})
				checkLongErrorScreen(t, fmt.Sprintf("%s standalone %v %s", screen.name, standalone, msgs.name), m, msgs, screen.selected)
			}
		}
	}
}
