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
	if got.manualLockConfirmFocus != 0 {
		t.Fatalf("manualLockConfirmFocus = %d, want 0", got.manualLockConfirmFocus)
	}
	if got.manualLockReturnView != ViewKeyList {
		t.Fatalf("manualLockReturnView = %v, want ViewKeyList", got.manualLockReturnView)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}

func TestLockConfirmStartsManualLock(t *testing.T) {
	m := Model{
		viewState:              ViewLockConfirm,
		manualLockReturnView:   ViewKeyList,
		manualLockConfirmFocus: 1,
	}

	next, cmd := m.handleLockConfirmKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
	}
	if !got.manualLockPending {
		t.Fatal("manualLockPending = false, want true")
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want lock request command")
	}
}

func TestManualLockFailureDoesNotScheduleIdleRetry(t *testing.T) {
	m := activityReadyModel()
	m.manualLockPending = true
	m.localIdleLockSent = true
	m.localIdleLockRetryDelay = 0

	next, _ := m.Update(LockIdentityResultMsg{
		Success: false,
		Error:   "authorization denied",
	})
	got := next.(Model)
	if got.manualLockPending {
		t.Fatal("manualLockPending = true, want false")
	}
	if got.localIdleLockRetryDelay != 0 || !got.localIdleLockRetryAt.IsZero() {
		t.Fatalf("idle retry scheduled after manual lock failure: delay=%v at=%v", got.localIdleLockRetryDelay, got.localIdleLockRetryAt)
	}
	if !strings.Contains(got.lastError, "Lock failed: authorization denied") {
		t.Fatalf("lastError = %q", got.lastError)
	}
}
