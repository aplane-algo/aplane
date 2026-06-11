// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestKeyListLockShortcutOpensLockConfirm(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
	}

	next, cmd := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	got := next.(Model)
	if got.viewState != ViewLockConfirm {
		t.Fatalf("viewState = %v, want ViewLockConfirm", got.viewState)
	}
	if got.manualLock.focus != 0 {
		t.Fatalf("manualLockConfirmFocus = %d, want 0", got.manualLock.focus)
	}
	if got.manualLock.returnView != ViewKeyList {
		t.Fatalf("manualLockReturnView = %v, want ViewKeyList", got.manualLock.returnView)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}

func TestLockConfirmStartsManualLock(t *testing.T) {
	m := Model{
		viewState:  ViewLockConfirm,
		manualLock: manualLockState{returnView: ViewKeyList, focus: 1},
	}

	next, cmd := m.handleLockConfirmKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
	}
	if !got.manualLock.pending {
		t.Fatal("manualLockPending = false, want true")
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want lock request command")
	}
}

func TestManualLockFailureDoesNotAffectIdleDisconnectState(t *testing.T) {
	m := activityReadyModel()
	m.manualLock.pending = true
	m.activity.idleDisconnectSent = true

	next, _ := m.Update(LockIdentityResultMsg{
		Success: false,
		Error:   "authorization denied",
	})
	got := next.(Model)
	if got.manualLock.pending {
		t.Fatal("manualLockPending = true, want false")
	}
	if !got.activity.idleDisconnectSent {
		t.Fatal("manual lock failure changed localIdleDisconnectSent")
	}
	if !strings.Contains(got.lastError, "Lock failed: authorization denied") {
		t.Fatalf("lastError = %q", got.lastError)
	}
}
