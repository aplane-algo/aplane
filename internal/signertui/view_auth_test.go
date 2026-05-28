// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
	"time"
)

func TestUnlockViewShowsSignerInactivityTimeout(t *testing.T) {
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
	if !strings.Contains(view, "Signer locks after 15m0s of admin inactivity") {
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
	if !strings.Contains(view, "Signer locks after 15m0s of admin inactivity") {
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
