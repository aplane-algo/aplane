// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func activityReadyModel() Model {
	return Model{
		viewState:           ViewKeyList,
		connectionState:     ConnectionConnected,
		adminClient:         &IPCClient{},
		signerStatusKnown:   true,
		signerLocked:        false,
		passphraseMasked:    true,
		restoreSelected:     map[string]bool{},
		importMnemonicInput: newImportMnemonicInput(),
	}
}

func TestRecordUserActivitySendsFirstReportImmediately(t *testing.T) {
	m := activityReadyModel()
	now := time.Now()

	got, cmd := m.recordUserActivity(now, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})

	if cmd == nil {
		t.Fatal("recordUserActivity returned nil cmd, want immediate activity report")
	}
	if got.activityReportPending {
		t.Fatal("activityReportPending = true, want false after immediate report")
	}
	if got.activityReportArmed {
		t.Fatal("activityReportArmed = true, want false after immediate report")
	}
	if !got.lastActivityReportAt.Equal(now) {
		t.Fatalf("lastActivityReportAt = %v, want %v", got.lastActivityReportAt, now)
	}
}

func TestRecordUserActivityKeepsActivityTickSingleFlight(t *testing.T) {
	m := activityReadyModel()
	now := time.Now()
	m.lastActivityReportAt = now

	got, cmd := m.recordUserActivity(now.Add(time.Second), tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if cmd == nil {
		t.Fatal("first throttled activity returned nil cmd, want tick")
	}
	if !got.activityReportArmed || !got.activityReportPending {
		t.Fatalf("activity state = armed %v pending %v, want both true", got.activityReportArmed, got.activityReportPending)
	}
	generation := got.activityReportGeneration
	dueAt := got.activityReportDueAt

	got, _ = got.recordUserActivity(now.Add(2*time.Second), tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	if got.activityReportGeneration != generation {
		t.Fatalf("activity generation = %d, want unchanged %d", got.activityReportGeneration, generation)
	}
	if !got.activityReportDueAt.Equal(dueAt) {
		t.Fatalf("activity dueAt = %v, want unchanged %v", got.activityReportDueAt, dueAt)
	}
}

func TestActivityReportTickIgnoresStaleAndEmptyTicks(t *testing.T) {
	m := activityReadyModel()
	now := time.Now()
	m.lastActivityReportAt = now.Add(-activityReportInterval)
	m.lastUserInputAt = now
	m.activityReportPending = true
	m.activityReportArmed = true
	m.activityReportGeneration = 4
	m.activityReportDueAt = now

	cmd := m.handleActivityReportTick(activityReportTickMsg{
		Generation: 3,
		DueAt:      now,
	})
	if cmd != nil {
		t.Fatal("stale activity tick returned cmd, want nil")
	}
	if !m.activityReportArmed || !m.activityReportPending {
		t.Fatalf("stale tick mutated state: armed %v pending %v", m.activityReportArmed, m.activityReportPending)
	}

	m.activityReportPending = false
	cmd = m.handleActivityReportTick(activityReportTickMsg{
		Generation: 4,
		DueAt:      now,
	})
	if cmd != nil {
		t.Fatal("empty activity tick returned cmd, want nil")
	}
}

func TestKeystrokeAfterReportWindowSendsActivity(t *testing.T) {
	m := activityReadyModel()
	now := time.Now()
	m.lastActivityReportAt = now.Add(-activityReportInterval)

	got, cmd := m.recordUserActivity(now, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})

	if cmd == nil {
		t.Fatal("recordUserActivity returned nil cmd, want activity report after throttle window")
	}
	if !got.lastActivityReportAt.Equal(now) {
		t.Fatalf("lastActivityReportAt = %v, want %v", got.lastActivityReportAt, now)
	}
	if got.activityReportPending || got.activityReportArmed {
		t.Fatalf("activity state = pending %v armed %v, want both false after report", got.activityReportPending, got.activityReportArmed)
	}
}

func TestRecordUserActivityIgnoresUnlockViewAndSignResponseKeys(t *testing.T) {
	now := time.Now()

	unlock := activityReadyModel()
	unlock.viewState = ViewUnlock
	got, cmd := unlock.recordUserActivity(now, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	if cmd != nil || !got.lastUserInputAt.IsZero() || got.activityReportPending {
		t.Fatalf("unlock activity state = %+v cmd %v, want ignored", got, cmd)
	}

	signing := activityReadyModel()
	signing.viewState = ViewSigningPopup
	got, cmd = signing.recordUserActivity(now, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd != nil || !got.lastUserInputAt.IsZero() || got.activityReportPending {
		t.Fatalf("sign response activity state = %+v cmd %v, want ignored", got, cmd)
	}
}

func TestUpdateIgnoresUnlockTypingEvenWithStaleUnlockedState(t *testing.T) {
	m := activityReadyModel()
	m.viewState = ViewUnlock
	m.signerLocked = false
	m.signerStatusKnown = true

	got, _ := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})

	if !got.lastUserInputAt.IsZero() || got.activityReportPending {
		t.Fatalf("unlock typing activity state = last %v pending %v, want ignored", got.lastUserInputAt, got.activityReportPending)
	}
	if got.passphraseInput != "s" {
		t.Fatalf("passphraseInput = %q, want key still handled by unlock view", got.passphraseInput)
	}
}

func TestUpdateCountsRestorePreviewNavigationAsActivity(t *testing.T) {
	m := activityReadyModel()
	m.viewState = ViewRestorePreview
	m.restorePreviewKeys = []RestoreKeyInfo{
		{Address: "ADDR1", KeyType: "ed25519"},
		{Address: "ADDR2", KeyType: "ed25519"},
	}
	m.restoreSelected = map[string]bool{"ADDR1": true}

	got, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyDown})

	if got.lastUserInputAt.IsZero() {
		t.Fatal("restore preview navigation did not record activity")
	}
	if got.selectedKey == 0 && got.restoreSelectedKey == 0 {
		t.Fatal("restore preview key was not handled")
	}
	if cmd == nil {
		t.Fatal("restore preview navigation cmd = nil, want immediate activity report")
	}
}

func TestNonKeyMessagesDoNotRecordActivity(t *testing.T) {
	m := activityReadyModel()

	got, _ := updateForTest(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	if !got.lastUserInputAt.IsZero() || got.activityReportPending {
		t.Fatalf("window resize recorded activity: last %v pending %v", got.lastUserInputAt, got.activityReportPending)
	}

	got, _ = updateForTest(t, got, AdminSettingsMsg{
		Settings: AdminSettings{
			PassphraseTimeout: "5m",
			Theme:             "auto",
		},
	})
	if !got.lastUserInputAt.IsZero() || got.activityReportPending {
		t.Fatalf("admin settings recorded activity: last %v pending %v", got.lastUserInputAt, got.activityReportPending)
	}

	got, _ = updateForTest(t, got, adminRefreshTickMsg{})
	if !got.lastUserInputAt.IsZero() || got.activityReportPending {
		t.Fatalf("admin refresh tick recorded activity: last %v pending %v", got.lastUserInputAt, got.activityReportPending)
	}

	got, _ = updateForTest(t, got, tea.MouseMsg{})
	if !got.lastUserInputAt.IsZero() || got.activityReportPending {
		t.Fatalf("mouse event recorded activity: last %v pending %v", got.lastUserInputAt, got.activityReportPending)
	}
}

func TestLocalIdleTickDisconnectsAdminWhenIdle(t *testing.T) {
	m := activityReadyModel()
	m.effectiveSessionTimeout = time.Millisecond
	m.lastUserInputAt = time.Now().Add(-time.Second)
	_ = m.armLocalIdleTimer()

	cmd := m.handleLocalIdleTick(localIdleTickMsg{
		Generation: m.localIdleGeneration,
		DueAt:      m.localIdleDueAt,
	})

	if cmd == nil {
		t.Fatal("handleLocalIdleTick returned nil cmd, want disconnect command")
	}
	if !m.localIdleDisconnectSent {
		t.Fatal("localIdleDisconnectSent = false, want true")
	}
	msg := cmd()
	if got, ok := msg.(localIdleDisconnectedMsg); !ok || got.Reason != localIdleDisconnectReason {
		t.Fatalf("disconnect cmd message = %#v, want local idle disconnect", msg)
	}
}

func TestLocalIdleTickIgnoresStaleTickAfterNewerKeystroke(t *testing.T) {
	m := activityReadyModel()
	m.effectiveSessionTimeout = time.Second
	m.lastUserInputAt = time.Now().Add(-2 * time.Second)
	_ = m.armLocalIdleTimer()
	oldGeneration := m.localIdleGeneration
	oldDueAt := m.localIdleDueAt

	m.lastUserInputAt = time.Now()
	_ = m.armLocalIdleTimer()
	cmd := m.handleLocalIdleTick(localIdleTickMsg{
		Generation: oldGeneration,
		DueAt:      oldDueAt,
	})

	if cmd != nil {
		t.Fatal("stale local idle tick returned cmd, want nil")
	}
	if m.localIdleDisconnectSent {
		t.Fatal("stale local idle tick set localIdleDisconnectSent")
	}
}

func TestLocalIdleDisconnectedMsgMarksDisconnectedWithoutLocking(t *testing.T) {
	m := activityReadyModel()
	m.lastUserInputAt = time.Now()
	m.localIdleDisconnectSent = true

	got, _ := updateForTest(t, m, localIdleDisconnectedMsg{Reason: localIdleDisconnectReason})

	if got.connectionState != ConnectionDisconnected {
		t.Fatalf("connectionState = %v, want disconnected", got.connectionState)
	}
	if got.signerLocked {
		t.Fatal("signerLocked = true, want unchanged false")
	}
	if got.signerStatusKnown {
		t.Fatal("signerStatusKnown = true, want unknown after local disconnect")
	}
	if got.lastWarning != localIdleDisconnectReason {
		t.Fatalf("lastWarning = %q, want %q", got.lastWarning, localIdleDisconnectReason)
	}
	assertActivityStateCleared(t, got)

	reconnecting, cmd := updateForTest(t, got, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if reconnecting.lastWarning != "" {
		t.Fatalf("lastWarning after reconnect key = %q, want cleared", reconnecting.lastWarning)
	}
	if reconnecting.connectionState != ConnectionConnecting {
		t.Fatalf("connectionState after reconnect key = %v, want connecting", reconnecting.connectionState)
	}
	if cmd == nil {
		t.Fatal("reconnect key cmd = nil, want reconnect command")
	}
}

func TestAdminSettingsRearmsKnownTimeoutAfterFreshUnlock(t *testing.T) {
	m := activityReadyModel()
	m.effectiveSessionTimeout = time.Second
	m.lastUserInputAt = time.Now()

	cmd := m.applyAdminSettingsTimeout(AdminSettings{PassphraseTimeout: "1s"})

	if cmd == nil {
		t.Fatal("applyAdminSettingsTimeout returned nil cmd, want idle timer")
	}
	if m.localIdleDueAt.IsZero() {
		t.Fatal("localIdleDueAt is zero, want idle due time")
	}
}

func TestDisconnectAndServerLockClearActivityAndSensitiveRestoreState(t *testing.T) {
	m := activityReadyModel()
	m.lastUserInputAt = time.Now()
	m.lastActivityReportAt = time.Now()
	m.activityReportPending = true
	m.activityReportArmed = true
	m.activityReportDueAt = time.Now().Add(time.Second)
	m.localIdleDisconnectSent = true
	m.localIdleDueAt = time.Now().Add(time.Second)

	got, _ := updateForTest(t, m, DisconnectedMsg{})
	if !got.lastUserInputAt.IsZero() ||
		!got.lastActivityReportAt.IsZero() ||
		got.activityReportPending ||
		got.activityReportArmed ||
		got.localIdleDisconnectSent ||
		!got.localIdleDueAt.IsZero() {
		t.Fatalf("disconnect did not clear activity state: %+v", got)
	}

	passphrase := []byte("export-passphrase")
	m = activityReadyModel()
	m.viewState = ViewRestorePreview
	m.restorePassphrase = passphrase
	got, _ = updateForTest(t, m, SignerStatusMsg{Locked: true})
	if got.viewState != ViewUnlock || !got.signerLocked {
		t.Fatalf("server lock state = view %v locked %v, want unlock locked", got.viewState, got.signerLocked)
	}
	if len(got.restorePassphrase) != 0 {
		t.Fatalf("restorePassphrase length = %d, want 0", len(got.restorePassphrase))
	}
	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("passphrase byte %d = %d, want zero", i, b)
		}
	}
}

func TestReconnectAndAuthRequiredClearActivityState(t *testing.T) {
	m := activityReadyModel()
	m.lastUserInputAt = time.Now()
	m.lastActivityReportAt = time.Now()
	m.activityReportPending = true
	m.activityReportArmed = true
	m.localIdleDisconnectSent = true
	m.localIdleDueAt = time.Now().Add(time.Second)

	got, _ := updateForTest(t, m, ReconnectingMsg{Delay: time.Second})
	if got.connectionState != ConnectionConnecting {
		t.Fatalf("connectionState = %v, want ConnectionConnecting", got.connectionState)
	}
	assertActivityStateCleared(t, got)

	m = activityReadyModel()
	m.lastUserInputAt = time.Now()
	m.activityReportPending = true
	m.localIdleDisconnectSent = true
	got, _ = updateForTest(t, m, AuthRequiredMsg{})
	if got.viewState != ViewAuth {
		t.Fatalf("viewState = %v, want ViewAuth", got.viewState)
	}
	assertActivityStateCleared(t, got)
}

func assertActivityStateCleared(t *testing.T, m Model) {
	t.Helper()
	if !m.lastUserInputAt.IsZero() ||
		!m.lastActivityReportAt.IsZero() ||
		m.activityReportPending ||
		m.activityReportArmed ||
		m.localIdleDisconnectSent ||
		!m.localIdleDueAt.IsZero() {
		t.Fatalf("activity state not cleared: %+v", m)
	}
}
