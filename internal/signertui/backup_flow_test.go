// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestKeyListBackupShortcutOpensBackupConfirm(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
	}

	next, _ := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	got := next.(Model)
	if got.viewState != ViewBackupConfirm {
		t.Fatalf("viewState = %v, want ViewBackupConfirm", got.viewState)
	}
	if got.backupConfirmFocus != 0 {
		t.Fatalf("backupConfirmFocus = %d, want 0", got.backupConfirmFocus)
	}
}

func TestBackupConfirmMatchingPassphrasesStartsBackup(t *testing.T) {
	m := Model{
		viewState:               ViewBackupConfirm,
		backupExportPassphrase:  "export-passphrase",
		backupConfirmPassphrase: "export-passphrase",
		backupConfirmFocus:      1,
	}

	next, cmd := m.handleBackupConfirmKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewBackingUp {
		t.Fatalf("viewState = %v, want ViewBackingUp", got.viewState)
	}
	if got.backupConfirmError != "" {
		t.Fatalf("backupConfirmError = %q, want empty", got.backupConfirmError)
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want backup send command")
	}
}

func TestBackupConfirmCancelReturnsToKeyList(t *testing.T) {
	m := Model{
		viewState:               ViewBackupConfirm,
		backupExportPassphrase:  "export-passphrase",
		backupConfirmPassphrase: "export-passphrase",
		backupConfirmError:      "old error",
	}

	next, cmd := m.handleBackupConfirmKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
	}
	if got.backupExportPassphrase != "" || got.backupConfirmPassphrase != "" || got.backupConfirmError != "" {
		t.Fatalf("backup confirm state was not cleared: %+v", got)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}

func TestBackupResultSuccessShowsArchivePath(t *testing.T) {
	m := Model{viewState: ViewBackingUp}
	archivePath := filepath.Join(t.TempDir(), "backups", "default", "backup.tar.gz")

	next, _ := m.Update(BackupResultMsg{
		Success:     true,
		ArchivePath: archivePath,
	})
	got := next.(Model)
	if got.viewState != ViewBackupDisplay {
		t.Fatalf("viewState = %v, want ViewBackupDisplay", got.viewState)
	}
	if got.backupArchivePath == "" {
		t.Fatal("backupArchivePath is empty")
	}
}

func TestBackupDisplayCloseReturnsToKeyList(t *testing.T) {
	m := Model{
		viewState:         ViewBackupDisplay,
		backupArchivePath: filepath.Join(t.TempDir(), "backups", "default", "aplane-backup.tar.gz"),
	}

	next, cmd := m.handleBackupDisplayKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
	}
	if got.backupArchivePath != "" {
		t.Fatalf("backupArchivePath = %q, want empty", got.backupArchivePath)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}
