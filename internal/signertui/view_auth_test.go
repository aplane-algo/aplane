// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestUnlockViewShowsAdminInactivityTimeout(t *testing.T) {
	m := Model{
		viewState:               ViewUnlock,
		connectionState:         ConnectionConnected,
		passphraseMasked:        true,
		effectiveSessionTimeout: 15 * time.Minute,
		importMnemonicInput:     newImportMnemonicInput(),
	}

	view := stripANSI(m.renderUnlockView())
	if !strings.Contains(view, "Enter passphrase to unlock Signer") {
		t.Fatalf("unlock view missing prompt:\n%s", view)
	}
	if !strings.Contains(view, "Admin disconnects after 15m0s of inactivity") {
		t.Fatalf("unlock view missing inactivity timeout:\n%s", view)
	}
}

func TestUnlockViewUsesAdminSettingsTimeoutBeforeIdleTimerApplied(t *testing.T) {
	m := Model{
		viewState:           ViewUnlock,
		connectionState:     ConnectionConnected,
		passphraseMasked:    true,
		importMnemonicInput: newImportMnemonicInput(),
		adminSettings:       &AdminSettings{PassphraseTimeout: "15m"},
	}

	view := stripANSI(m.renderUnlockView())
	if !strings.Contains(view, "Admin disconnects after 15m0s of inactivity") {
		t.Fatalf("unlock view missing admin settings timeout:\n%s", view)
	}
}

func TestStatusBarLabelsSignerLockState(t *testing.T) {
	locked := stripANSI(Model{
		connectionState:   ConnectionConnected,
		signerStatusKnown: true,
		signerLocked:      true,
	}.renderStatusBar())
	if !strings.Contains(locked, "Signer Locked") {
		t.Fatalf("locked status missing signer label: %q", locked)
	}

	unlocked := stripANSI(Model{
		connectionState:   ConnectionConnected,
		signerStatusKnown: true,
		signerLocked:      false,
		keyCount:          3,
	}.renderStatusBar())
	if !strings.Contains(unlocked, "Signer Unlocked (3 keys)") {
		t.Fatalf("unlocked status missing signer label: %q", unlocked)
	}
}

func TestPassphraseEntryAcceptsLetterQ(t *testing.T) {
	m := Model{
		viewState:       ViewUnlock,
		connectionState: ConnectionConnected,
	}

	model, _ := m.handlePassphraseKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}, func(string) tea.Cmd { return nil })
	updated := model.(Model)

	if updated.quitting {
		t.Fatal("typing 'q' on a passphrase screen must not quit")
	}
	if updated.passphraseInput != "q" {
		t.Fatalf("passphrase input = %q, want %q", updated.passphraseInput, "q")
	}
}

func TestPassphraseEntryEscQuits(t *testing.T) {
	m := Model{
		viewState:       ViewUnlock,
		connectionState: ConnectionConnected,
	}

	model, _ := m.handlePassphraseKeys(tea.KeyMsg{Type: tea.KeyEsc}, func(string) tea.Cmd { return nil })
	if !model.(Model).quitting {
		t.Fatal("esc on a passphrase screen should quit")
	}
}
