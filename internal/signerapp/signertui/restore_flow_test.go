// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestKeyListRestoreShortcutOpensRestoreList(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
	}

	next, cmd := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	got := next.(Model)
	if got.viewState != ViewRestoreList {
		t.Fatalf("viewState = %v, want ViewRestoreList", got.viewState)
	}
	if got.restore.backupsLoaded {
		t.Fatal("restoreBackupsLoaded = true, want false while list request is in flight")
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want backup list command")
	}
}

func TestRestoreListCancelReturnsToKeyList(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backups", "default", "aplane-backup.tar.gz")
	m := Model{
		viewState: ViewRestoreList,
		restore: restoreState{backupsLoaded: true, backups: []BackupInfo{{
			Path:     archivePath,
			FileName: "aplane-backup.tar.gz",
		}}, selectedBackup: 0},
	}

	next, cmd := m.handleRestoreListKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
	}
	if got.restore.backupsLoaded || len(got.restore.backups) != 0 {
		t.Fatalf("restore list state was not reset: %+v", got)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}

func TestRenderRestoreListShowsBackupDirectory(t *testing.T) {
	dataDir := t.TempDir()
	m := Model{
		width:     120,
		height:    30,
		dataDir:   dataDir,
		viewState: ViewRestoreList,
		restore: restoreState{backupsLoaded: true, backups: []BackupInfo{{
			Path:     filepath.Join(dataDir, "backups", "default", "aplane-backup.tar.gz"),
			FileName: "aplane-backup.tar.gz",
			Size:     4096,
		}}},
	}

	view := stripANSI(m.renderRestoreList())
	wantPath := filepath.Join(dataDir, "backups") + string(filepath.Separator)
	if !strings.Contains(view, "Backup Directory:") || !strings.Contains(view, wantPath) {
		t.Fatalf("restore list missing backup directory:\n%s", view)
	}
}

func TestBackupsListResponsePopulatesRestoreBrowser(t *testing.T) {
	m := Model{viewState: ViewRestoreList}
	archivePath := filepath.Join(t.TempDir(), "backups", "default", "backup.tar.gz")

	next, _ := m.Update(BackupsListMsg{
		Backups: []BackupInfo{{
			Path:     archivePath,
			FileName: "backup.tar.gz",
			Size:     4096,
		}},
	})
	got := next.(Model)
	if got.viewState != ViewRestoreList {
		t.Fatalf("viewState = %v, want ViewRestoreList", got.viewState)
	}
	if !got.restore.backupsLoaded {
		t.Fatal("restoreBackupsLoaded = false, want true")
	}
	if len(got.restore.backups) != 1 || got.restore.backups[0].FileName != "backup.tar.gz" {
		t.Fatalf("restoreBackups = %+v, want backup.tar.gz", got.restore.backups)
	}
}

func TestRestorePreviewPreselectsOnlyNewKeysAndKeepsPassphrase(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "aplane-backup.tar.gz")
	m := Model{
		viewState: ViewRestorePassphrase,
		restore:   restoreState{archivePath: archivePath, passphrase: []byte("export-passphrase"), previewing: true},
	}

	next, _ := m.Update(RestorePreviewMsg{
		ArchivePath: archivePath,
		Keys: []RestoreKeyInfo{
			{Address: "NEWADDR", KeyType: "ed25519"},
			{Address: "EXISTINGADDR", KeyType: "ed25519", AlreadyExists: true},
		},
	})
	got := next.(Model)
	if got.viewState != ViewRestorePreview {
		t.Fatalf("viewState = %v, want ViewRestorePreview", got.viewState)
	}
	if got.restore.previewing {
		t.Fatal("restorePreviewing = true, want false")
	}
	if string(got.restore.passphrase) != "export-passphrase" {
		t.Fatalf("restorePassphrase = %q, want retained passphrase for restore", string(got.restore.passphrase))
	}
	if !got.restore.selected["NEWADDR"] {
		t.Fatal("new key was not preselected")
	}
	if got.restore.selected["EXISTINGADDR"] {
		t.Fatal("existing key was preselected without overwrite")
	}
}

func TestRestorePreviewFailureClearsPassphrase(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "aplane-backup.tar.gz")
	passphrase := []byte("export-passphrase")
	m := Model{
		viewState: ViewRestorePassphrase,
		restore:   restoreState{archivePath: archivePath, passphrase: passphrase, previewing: true},
	}

	next, _ := m.Update(RestorePreviewMsg{
		Errors: []RestoreError{{Error: "invalid backup export passphrase"}},
	})
	got := next.(Model)
	if got.viewState != ViewRestorePassphrase {
		t.Fatalf("viewState = %v, want ViewRestorePassphrase", got.viewState)
	}
	if got.restore.previewing {
		t.Fatal("restorePreviewing = true, want false")
	}
	if len(got.restore.passphrase) != 0 {
		t.Fatalf("restorePassphrase length = %d, want 0", len(got.restore.passphrase))
	}
	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("passphrase byte %d = %d, want zero", i, b)
		}
	}
	if got.restore.passphraseError == "" {
		t.Fatal("restorePassphraseError is empty")
	}
}

func TestRestorePreviewSelectsExistingKeysFreely(t *testing.T) {
	// Recovery is inactive and never overwrites anything: conflict rows are
	// informational, and the replace-existing consent lives on the
	// restore confirmation beside the exact conflicts it authorizes.
	m := Model{
		viewState: ViewRestorePreview,
		restore: restoreState{previewKeys: []RestoreKeyInfo{
			{Address: "EXISTINGADDR", KeyType: "ed25519", AlreadyExists: true},
		}, selected: make(map[string]bool)},
	}

	next, _ := m.handleRestorePreviewKeys(tea.KeyMsg{Type: tea.KeySpace})
	got := next.(Model)
	if !got.restore.selected["EXISTINGADDR"] {
		t.Fatal("existing key was not freely selectable on the preview")
	}
	if got.restore.previewError != "" {
		t.Fatalf("previewError = %q, want none for an informational conflict", got.restore.previewError)
	}

	view := got.renderRestorePreview()
	plain := stripANSI(view)
	if !strings.Contains(plain, "exists") {
		t.Fatalf("preview does not mark the conflicting key informationally:\n%s", plain)
	}
	if strings.Contains(plain, "Overwrite:") {
		t.Fatalf("preview still renders the removed overwrite toggle:\n%s", plain)
	}
}

func TestRestorePreviewRendersScrollableKeyWindowLikeKeyList(t *testing.T) {
	keys := make([]RestoreKeyInfo, 0, 6)
	for i := 0; i < 6; i++ {
		keys = append(keys, RestoreKeyInfo{
			Address: fmt.Sprintf("RESTOREADDR%02d", i),
			KeyType: "ed25519",
		})
	}
	m := Model{
		viewState: ViewRestorePreview,
		height:    16,
		restore:   restoreState{previewKeys: keys, selected: map[string]bool{"RESTOREADDR00": true}},
	}

	view := m.renderRestorePreview()
	if !strings.Contains(view, "> ") || !strings.Contains(view, "RESTOREADDR00") {
		t.Fatalf("rendered restore key list does not show selected key like main key list:\n%s", view)
	}
	if !strings.Contains(view, "▼ 4 more below") {
		t.Fatalf("rendered restore key list missing scroll-down indicator:\n%s", view)
	}
	if !strings.Contains(view, "Total: 6 keys") {
		t.Fatalf("rendered restore key list missing total count:\n%s", view)
	}
	if strings.Contains(view, "RESTOREADDR05") {
		t.Fatalf("rendered restore key list shows item outside visible window:\n%s", view)
	}

	for range 4 {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(Model)
	}
	if m.restore.previewScrollOffset == 0 {
		t.Fatal("restorePreviewScrollOffset = 0, want scrolled window")
	}

	view = m.renderRestorePreview()
	if !strings.Contains(view, "▲ 3 more above") {
		t.Fatalf("rendered restore key list missing scroll-up indicator:\n%s", view)
	}
	if !strings.Contains(view, "> ") || !strings.Contains(view, "RESTOREADDR04") {
		t.Fatalf("rendered restore key list does not keep selected key visible:\n%s", view)
	}
}

func TestRestorePreviewPopupFitsTerminalHeight(t *testing.T) {
	keys := make([]RestoreKeyInfo, 0, 8)
	selected := make(map[string]bool)
	for i := 0; i < 8; i++ {
		address := fmt.Sprintf("RESTOREADDR%02d", i)
		keys = append(keys, RestoreKeyInfo{
			Address: address,
			KeyType: "ed25519",
		})
		selected[address] = true
	}
	m := Model{
		viewState: ViewRestorePreview,
		width:     90,
		height:    16,
		restore:   restoreState{previewKeys: keys, selected: selected, selectedKey: 4, previewScrollOffset: 3},
	}

	view := m.renderRestorePreview()
	if lines := visibleLineCount(view); lines > m.height {
		t.Fatalf("restore preview line count = %d, want <= %d\n%s", lines, m.height, stripANSI(view))
	}
	if !strings.Contains(stripANSI(view), "▲ 3 more above") || !strings.Contains(stripANSI(view), "▼ 3 more below") {
		t.Fatalf("height-constrained restore preview missing scroll indicators:\n%s", stripANSI(view))
	}
}

func TestRestorePreviewReservesContinuationRows(t *testing.T) {
	noContinuation := Model{
		viewState: ViewRestorePreview,
		width:     90,
		height:    16,
		restore: restoreState{previewKeys: []RestoreKeyInfo{
			{Address: "RESTOREADDR00", KeyType: "ed25519"},
			{Address: "RESTOREADDR01", KeyType: "ed25519"},
		}, selected: map[string]bool{"RESTOREADDR00": true}},
	}

	keys := make([]RestoreKeyInfo, 0, 8)
	selected := make(map[string]bool)
	for i := 0; i < 8; i++ {
		address := fmt.Sprintf("RESTOREADDR%02d", i)
		keys = append(keys, RestoreKeyInfo{
			Address: address,
			KeyType: "ed25519",
		})
		selected[address] = true
	}
	withContinuation := Model{
		viewState: ViewRestorePreview,
		width:     90,
		height:    16,
		restore:   restoreState{previewKeys: keys, selected: selected, selectedKey: 4, previewScrollOffset: 3},
	}

	noContinuationView := noContinuation.renderRestorePreview()
	withContinuationView := withContinuation.renderRestorePreview()
	if strings.Contains(stripANSI(noContinuationView), "more above") || strings.Contains(stripANSI(noContinuationView), "more below") {
		t.Fatalf("restore preview without continuation unexpectedly rendered indicator text:\n%s", stripANSI(noContinuationView))
	}
	if got, want := visibleLineCount(noContinuationView), visibleLineCount(withContinuationView); got != want {
		t.Fatalf("restore preview line count without continuation = %d, with continuation = %d\nwithout:\n%s\nwith:\n%s",
			got, want, stripANSI(noContinuationView), stripANSI(withContinuationView))
	}
}

func TestRestoreDisplayPopupFitsTerminalHeightAndScrollsRestoredKeys(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backups", "default", "aplane-backup.tar.gz")
	restored := make([]RestoreKeyInfo, 0, 8)
	for i := 0; i < 8; i++ {
		restored = append(restored, RestoreKeyInfo{
			Address: fmt.Sprintf("RESTOREDADDR%02d", i),
			KeyType: "ed25519",
		})
	}
	m := Model{
		viewState: ViewRestoreDisplay,
		width:     90,
		height:    21,
		restore: restoreState{result: RestoreDisplayResult{
			ArchivePath: archivePath,
			Activated:   restored,
			Success:     true,
		}},
	}

	view := m.renderRestoreDisplay()
	clean := stripANSI(view)
	if lines := visibleLineCount(view); lines > m.height {
		t.Fatalf("restore display line count = %d, want <= %d\n%s", lines, m.height, clean)
	}
	if !strings.Contains(clean, "▼") || !strings.Contains(clean, "more below") {
		t.Fatalf("restore display missing scroll-down indicator:\n%s", clean)
	}
	if strings.Contains(clean, "RESTOREDADDR07") {
		t.Fatalf("restore display shows key outside initial window:\n%s", clean)
	}
	if !strings.Contains(clean, "> RESTOREDADDR00  [ed25519]") {
		t.Fatalf("restore display missing selected cursor on first row:\n%s", clean)
	}

	for range 5 {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(Model)
	}
	view = m.renderRestoreDisplay()
	clean = stripANSI(view)
	if lines := visibleLineCount(view); lines > m.height {
		t.Fatalf("scrolled restore display line count = %d, want <= %d\n%s", lines, m.height, clean)
	}
	if !strings.Contains(clean, "▲") || !strings.Contains(clean, "more above") {
		t.Fatalf("scrolled restore display missing scroll-up indicator:\n%s", clean)
	}
	if !strings.Contains(clean, "RESTOREDADDR05") {
		t.Fatalf("scrolled restore display missing later restored key:\n%s", clean)
	}
	if !strings.Contains(clean, "> RESTOREDADDR05  [ed25519]") {
		t.Fatalf("scrolled restore display did not move cursor to later key:\n%s", clean)
	}
}

func TestRestoreSubmitClearsPassphrase(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "aplane-backup.tar.gz")
	passphrase := []byte("export-passphrase")
	m := Model{
		viewState: ViewRestorePreview,
		restore: restoreState{archivePath: archivePath, passphrase: passphrase, previewKeys: []RestoreKeyInfo{
			{Address: "NEWADDR", KeyType: "ed25519"},
		}, selected: map[string]bool{"NEWADDR": true}, previewFocus: restoreFocusAction},
	}

	next, cmd := m.handleRestorePreviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewRestoring {
		t.Fatalf("viewState = %v, want ViewRestoring", got.viewState)
	}
	if len(got.restore.passphrase) != 0 {
		t.Fatalf("restorePassphrase length = %d, want 0", len(got.restore.passphrase))
	}
	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("passphrase byte %d = %d, want zero", i, b)
		}
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want restore command")
	}
}

func TestRestoreConflictConfirmationKeepsSelectorsVisibleWhileTyping(t *testing.T) {
	m := Model{
		viewState: ViewRestoring,
		restore: restoreState{
			archivePath: "backup.tar.gz",
			selected:    map[string]bool{"CONFLICT1": true, "CONFLICT2": true},
		},
	}
	got, _ := updateForTest(t, m, RestoreBackupResultMsg{Result: RestoreBackupResultMessage{
		Code: protocol.ResultCodeRestoreConflict,
		Conflicts: []RestoreConflict{
			{Selector: "CONFLICT1", KeyType: "ed25519"},
			{Selector: "CONFLICT2", KeyType: "example.lsig.v1"},
		},
	}})
	if !got.restore.replaceExisting || got.viewState != ViewRestorePassphrase {
		t.Fatalf("conflict result = replace %v view %v", got.restore.replaceExisting, got.viewState)
	}

	next, _ := got.handleRestorePassphraseKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	got = next.(Model)
	view := stripANSI(got.renderRestorePassphrase())
	for _, want := range []string{"Confirm Credential Replacement", "CONFLICT1", "CONFLICT2", "will be replaced"} {
		if !strings.Contains(view, want) {
			t.Fatalf("replacement confirmation lost %q after typing:\n%s", want, view)
		}
	}
	if footer := got.viewFooterText(); !strings.Contains(footer, "Replace listed credentials") {
		t.Fatalf("replacement footer = %q", footer)
	}
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRE.ReplaceAllString(s, "")
}

func visibleWidth(s string) int {
	return len([]rune(stripANSI(s)))
}

func visibleLineCount(s string) int {
	return len(strings.Split(strings.TrimRight(stripANSI(s), "\n"), "\n"))
}

func updateForTest(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()

	next, cmd := m.Update(msg)
	got, ok := next.(Model)
	if !ok {
		t.Fatalf("Update(%T) returned %T, want Model", msg, next)
	}
	return got, cmd
}
