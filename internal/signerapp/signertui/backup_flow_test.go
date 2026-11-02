// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestBackupsPageNewOpensBackupConfirm(t *testing.T) {
	m := Model{viewState: ViewBackups, restore: restoreState{backupsLoaded: true}}

	next, _ := m.handleBackupsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	got := next.(Model)
	if got.viewState != ViewBackupConfirm {
		t.Fatalf("viewState = %v, want ViewBackupConfirm", got.viewState)
	}
	if got.backup.confirmFocus != 0 {
		t.Fatalf("backupConfirmFocus = %d, want 0", got.backup.confirmFocus)
	}
}

func TestBackupConfirmMatchingPassphrasesStartsBackup(t *testing.T) {
	m := Model{
		viewState: ViewBackupConfirm,
		backup:    backupState{exportPassphrase: "export-passphrase", confirmPassphrase: "export-passphrase", confirmFocus: 1},
	}

	next, cmd := m.handleBackupConfirmKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewBackingUp {
		t.Fatalf("viewState = %v, want ViewBackingUp", got.viewState)
	}
	if got.backup.confirmError != "" {
		t.Fatalf("backupConfirmError = %q, want empty", got.backup.confirmError)
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want backup send command")
	}
}

func TestBackupConfirmCancelReturnsToBackups(t *testing.T) {
	m := Model{
		viewState: ViewBackupConfirm,
		backup:    backupState{exportPassphrase: "export-passphrase", confirmPassphrase: "export-passphrase", confirmError: "old error"},
	}

	next, cmd := m.handleBackupConfirmKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewBackups {
		t.Fatalf("viewState = %v, want ViewBackups", got.viewState)
	}
	if got.backup.exportPassphrase != "" || got.backup.confirmPassphrase != "" || got.backup.confirmError != "" {
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
	if got.backup.archivePath == "" {
		t.Fatal("backupArchivePath is empty")
	}
}

func TestBackupDisplayCloseReturnsToBackupsSelectingTheNewBackup(t *testing.T) {
	m := Model{
		viewState: ViewBackupDisplay,
		backup: backupState{
			archivePath: "aplane-backup-20261102-070725.tar.gz",
		},
	}

	next, cmd := m.handleBackupDisplayKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewBackups || got.backups.selectName != "aplane-backup-20261102-070725.tar.gz" {
		t.Fatalf("viewState = %v selectName %q, want the Backups page selecting the new backup", got.viewState, got.backups.selectName)
	}
	if got.backup.archivePath != "" {
		t.Fatalf("backupArchivePath = %q, want empty", got.backup.archivePath)
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want the backup list refreshed")
	}
}
