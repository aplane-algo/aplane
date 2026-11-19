// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func allZero(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}

// typeSecret sends each rune of text as its own key and returns every backing
// array the field outgrew on the way, each in full.
func typeSecret(t *testing.T, m Model, text string, handle func(Model, tea.KeyMsg) Model, field func(Model) []byte) (Model, [][]byte) {
	t.Helper()
	var outgrown [][]byte
	for _, r := range text {
		before := field(m)
		m = handle(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		after := field(m)
		if cap(before) > 0 && cap(after) != cap(before) {
			outgrown = append(outgrown, before[:cap(before)])
		}
	}
	if got := string(field(m)); got != text {
		t.Fatalf("typed %q, field holds %q", text, got)
	}
	if len(outgrown) == 0 {
		t.Fatalf("typing %q never grew the field", text)
	}
	return m, outgrown
}

func assertOutgrownZeroed(t *testing.T, outgrown [][]byte) {
	t.Helper()
	for i, old := range outgrown {
		if !allZero(old) {
			t.Fatalf("outgrown buffer %d still holds %q", i, old)
		}
	}
}

const typedSecret = "correct horse battery staple"

// secretCmd's copy of the secret is zeroed once the command has run, and
// the caller's buffer is left for the caller to zero.
func TestSecretCmdZeroesItsCopyAfterRunning(t *testing.T) {
	secret := []byte("unlock-secret")
	var sent []byte
	cmd := secretCmd(secret, func(p []byte) tea.Cmd {
		return func() tea.Msg {
			sent = p
			return nil
		}
	})
	cmd()
	if len(sent) == 0 || !allZero(sent) {
		t.Fatalf("command left its copy as %q", sent)
	}
	if string(secret) != "unlock-secret" {
		t.Fatalf("command changed the caller's buffer to %q", secret)
	}
}

// TU12: the backup import passphrase grows without leaving copies behind.
func TestBackupImportPassphraseGrowthZeroesOutgrownBuffers(t *testing.T) {
	m := Model{viewState: ViewBackupImport}
	m.backups.imp.focus = importFocusPassphrase
	m, outgrown := typeSecret(t, m, typedSecret, func(m Model, k tea.KeyMsg) Model {
		next, _ := m.handleBackupImportKeys(k)
		return next.(Model)
	}, func(m Model) []byte { return m.backups.imp.passphrase })
	assertOutgrownZeroed(t, outgrown)

	full := m.backups.imp.passphrase[:cap(m.backups.imp.passphrase)]
	m = m.closeBackupImportForm()
	if !allZero(full) {
		t.Fatalf("closing the form left %q", full)
	}
}

// TU12: the restore passphrase grows without leaving copies behind.
func TestRestorePassphraseGrowthZeroesOutgrownBuffers(t *testing.T) {
	m := Model{viewState: ViewRestorePassphrase}
	_, outgrown := typeSecret(t, m, typedSecret, func(m Model, k tea.KeyMsg) Model {
		next, _ := m.handleRestorePassphraseKeys(k)
		return next.(Model)
	}, func(m Model) []byte { return m.restore.passphrase })
	assertOutgrownZeroed(t, outgrown)
}

// TU13: the login and unlock passphrase is a zeroable buffer, grown without
// copies, and zeroed when its result arrives and when the session ends.
func TestAuthPassphraseIsZeroedOnResultAndSessionEnd(t *testing.T) {
	m := Model{viewState: ViewAuth, connectionState: ConnectionConnected, auth: authState{passphraseMasked: true}}
	typeAuth := func(m Model) (Model, [][]byte) {
		return typeSecret(t, m, typedSecret, func(m Model, k tea.KeyMsg) Model {
			next, _ := m.handleAuthKeys(k)
			return next.(Model)
		}, func(m Model) []byte { return m.auth.passphraseInput })
	}

	m, outgrown := typeAuth(m)
	assertOutgrownZeroed(t, outgrown)
	full := m.auth.passphraseInput[:cap(m.auth.passphraseInput)]
	next, cmd := m.handleAuthKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil || !m.auth.loggingIn {
		t.Fatal("enter did not submit the passphrase")
	}
	next, _ = m.handleAuthResultMsg(AuthResultMsg{Success: true})
	m = next.(Model)
	if len(m.auth.passphraseInput) != 0 || !allZero(full) {
		t.Fatalf("a successful login left %q", full)
	}

	m.viewState = ViewAuth
	m, _ = typeAuth(m)
	full = m.auth.passphraseInput[:cap(m.auth.passphraseInput)]
	m.endAdminSession()
	if len(m.auth.passphraseInput) != 0 || !allZero(full) {
		t.Fatalf("the session end left %q", full)
	}
}

// TU13: the backup export and confirm passphrases are zeroable buffers,
// zeroed when the backup is requested and when the form is left.
func TestBackupConfirmPassphrasesAreZeroedOnSubmitAndEsc(t *testing.T) {
	typeBoth := func(m Model) (Model, []byte, []byte) {
		for focus := 0; focus < 2; focus++ {
			m.backup.confirmFocus = focus
			field := func(m Model) []byte { return m.backup.exportPassphrase }
			if focus == 1 {
				field = func(m Model) []byte { return m.backup.confirmPassphrase }
			}
			var outgrown [][]byte
			m, outgrown = typeSecret(t, m, typedSecret, func(m Model, k tea.KeyMsg) Model {
				next, _ := m.handleBackupConfirmKeys(k)
				return next.(Model)
			}, field)
			assertOutgrownZeroed(t, outgrown)
		}
		return m, m.backup.exportPassphrase[:cap(m.backup.exportPassphrase)], m.backup.confirmPassphrase[:cap(m.backup.confirmPassphrase)]
	}

	m, export, confirm := typeBoth(Model{viewState: ViewBackupConfirm})
	next, cmd := m.handleBackupConfirmKeys(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil || m.viewState != ViewBackingUp {
		t.Fatalf("enter did not request the backup (view %v)", m.viewState)
	}
	if len(m.backup.exportPassphrase) != 0 || !allZero(export) || !allZero(confirm) {
		t.Fatalf("submitting left export %q confirm %q", export, confirm)
	}

	m, export, confirm = typeBoth(Model{viewState: ViewBackupConfirm})
	next, _ = m.handleBackupConfirmKeys(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)
	if len(m.backup.confirmPassphrase) != 0 || !allZero(export) || !allZero(confirm) {
		t.Fatalf("leaving the form left export %q confirm %q", export, confirm)
	}
}

// watchSecretCopies records every copy secretCmd makes until the test ends.
func watchSecretCopies(t *testing.T) *[][]byte {
	t.Helper()
	var copies [][]byte
	original := newSecretCopy
	newSecretCopy = func(secret []byte) []byte {
		owned := original(secret)
		copies = append(copies, owned)
		return owned
	}
	t.Cleanup(func() { newSecretCopy = original })
	return &copies
}

// Every command that sends a secret zeroes its copy when it runs with no
// client connected, so the send closure inside it never runs.
func TestSecretCommandsZeroTheirCopyWhenNotConnected(t *testing.T) {
	m := Model{}
	tests := []struct {
		name  string
		build func(passphrase []byte) tea.Cmd
	}{
		{"auth", m.sendAuthCmd},
		{"unlock", m.sendUnlockCmd},
		{"backup", func(p []byte) tea.Cmd { return m.sendBackupCmd(p, "backup-1") }},
		{"preview restore", func(p []byte) tea.Cmd { return m.sendPreviewRestoreCmd("backup.tar.gz", p, "preview-1") }},
		{"restore", func(p []byte) tea.Cmd {
			return m.sendRestoreBackupCmd("backup.tar.gz", []string{"ADDR"}, p, false, "restore-1")
		}},
		{"commit backup import", func(p []byte) tea.Cmd {
			return m.sendCommitBackupImportCmd("commit-1", "upload-1", "backup.tar.gz", 10, "checksum", p)
		}},
		{"export key", func(p []byte) tea.Cmd {
			m := Model{viewState: ViewMnemonicExport}
			m.mnemonicExport.passphrase = append([]byte(nil), p...)
			_, cmd := m.handleMnemonicExportKeys(tea.KeyMsg{Type: tea.KeyEnter})
			return cmd
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copies := watchSecretCopies(t)
			passphrase := []byte("command-secret")
			cmd := tt.build(passphrase)
			if cmd == nil {
				t.Fatal("no command")
			}
			if msg, ok := cmd().(sendFailedMsg); !ok || msg.Error == nil {
				t.Fatalf("command returned %#v, want a not-connected failure", msg)
			}
			if len(*copies) == 0 {
				t.Fatal("the command made no copy of its secret through secretCmd")
			}
			for i, copied := range *copies {
				if len(copied) == 0 || !allZero(copied) {
					t.Fatalf("copy %d left as %q", i, copied)
				}
			}
			if string(passphrase) != "command-secret" {
				t.Fatalf("command changed the caller's buffer to %q", passphrase)
			}
		})
	}
}
