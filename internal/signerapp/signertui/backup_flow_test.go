// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"path/filepath"
	"strings"
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

func TestBackupConfirmCancelReturnsToKeyList(t *testing.T) {
	m := Model{
		viewState: ViewBackupConfirm,
		backup:    backupState{exportPassphrase: "export-passphrase", confirmPassphrase: "export-passphrase", confirmError: "old error"},
	}

	next, cmd := m.handleBackupConfirmKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
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

// TestBackupResultSurfacesSkippedKeys pins that skipped-key warnings from an
// all-keys backup reach the operator: they must land in model state and render
// prominently on the result screen, never a clean "Backup Created".
func TestBackupResultSurfacesSkippedKeys(t *testing.T) {
	m := Model{viewState: ViewBackingUp}
	const skippedAddress = "SKIPPEDKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	next, _ := m.Update(BackupResultMsg{
		Success:     true,
		ArchivePath: filepath.Join(t.TempDir(), "backup.tar.gz"),
		SkippedKeys: map[string]string{skippedAddress: "incompatible key file format"},
	})
	got := next.(Model)
	if got.viewState != ViewBackupDisplay {
		t.Fatalf("viewState = %v, want ViewBackupDisplay", got.viewState)
	}
	if len(got.backup.skippedKeys) != 1 {
		t.Fatalf("skippedKeys = %#v, want one entry", got.backup.skippedKeys)
	}

	view := got.renderBackupDisplay()
	if !strings.Contains(view, "Backup Created With Warnings") {
		t.Fatalf("view missing warning title:\n%s", view)
	}
	if !strings.Contains(view, "NOT backed up") || !strings.Contains(view, skippedAddress) {
		t.Fatalf("view missing skipped-key warning:\n%s", view)
	}
	if !strings.Contains(view, "incompatible key file format") {
		t.Fatalf("view missing skip reason:\n%s", view)
	}

	clean := Model{viewState: ViewBackupDisplay, backup: backupState{archivePath: "/tmp/a.tgz"}}
	if view := clean.renderBackupDisplay(); strings.Contains(view, "Warnings") {
		t.Fatalf("clean backup view should not mention warnings:\n%s", view)
	}
}

func TestBackupDisplayCloseReturnsToKeyList(t *testing.T) {
	m := Model{
		viewState: ViewBackupDisplay,
		backup: backupState{
			archivePath: filepath.Join(t.TempDir(), "backups", "default", "aplane-backup.tar.gz"),
			skippedKeys: map[string]string{"ADDR": "reason"},
		},
	}

	next, cmd := m.handleBackupDisplayKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
	}
	if got.backup.archivePath != "" {
		t.Fatalf("backupArchivePath = %q, want empty", got.backup.archivePath)
	}
	if got.backup.skippedKeys != nil {
		t.Fatalf("skippedKeys = %#v, want cleared", got.backup.skippedKeys)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}
