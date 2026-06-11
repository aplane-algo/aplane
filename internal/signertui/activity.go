// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	localIdleDisconnectReason = "apadmin disconnected after inactivity timeout"
	manualLockReason          = "apadmin manual lock"
)

func (m Model) recordUserActivity(now time.Time, msg tea.KeyMsg) (Model, tea.Cmd) {
	if !m.shouldTrackLocalIdle(msg) {
		return m, nil
	}

	m.lastUserInputAt = now
	m.localIdleDisconnectSent = false

	return m, m.armLocalIdleTimer()
}

func (m Model) shouldTrackLocalIdle(_ tea.KeyMsg) bool {
	return m.canTrackLocalIdle()
}

func (m Model) canTrackLocalIdle() bool {
	if m.connectionState != ConnectionConnected || m.adminClient == nil {
		return false
	}
	if !m.signerStatusKnown || m.signerLocked {
		return false
	}
	return m.viewState != ViewAuth && m.viewState != ViewUnlock
}

func (m *Model) resetActivityState() {
	m.lastUserInputAt = time.Time{}
	m.localIdleDisconnectSent = false
	m.localIdleGeneration++
	m.localIdleDueAt = time.Time{}
}

func (m *Model) applySignerLockedState() {
	m.clearRestorePassphrase()
	m.manualLockPending = false
	m.manualLockConfirmFocus = 0
	m.manualLockReturnView = ViewKeyList
	m.signerLocked = true
	m.signerStatusKnown = true
	m.viewState = ViewUnlock
	m.passphraseInput = ""
	m.passphraseError = ""
	m.resetActivityState()
}

func (m *Model) applySignerUnlockedState(keyCount int) {
	m.manualLockPending = false
	m.manualLockConfirmFocus = 0
	m.manualLockReturnView = ViewKeyList
	m.signerLocked = false
	m.signerStatusKnown = true
	m.keyCount = keyCount
	m.viewState = ViewKeyList
	m.resetActivityState()
	m.lastUserInputAt = time.Now()
}

func (m *Model) applyAdminSettingsTimeout(settings AdminSettings) tea.Cmd {
	timeout, err := serverconfig.ParsePassphraseTimeout(settings.PassphraseTimeout)
	if err != nil {
		m.effectiveSessionTimeout = 0
		m.localIdleGeneration++
		m.localIdleDueAt = time.Time{}
		m.setPersistentWarning("Invalid passphrase timeout from server: " + err.Error())
		return nil
	}

	if timeout == m.effectiveSessionTimeout {
		if m.localIdleDueAt.IsZero() {
			return m.armLocalIdleTimer()
		}
		return nil
	}
	m.effectiveSessionTimeout = timeout
	return m.armLocalIdleTimer()
}

func (m *Model) armLocalIdleTimer() tea.Cmd {
	if !m.canTrackLocalIdle() ||
		m.effectiveSessionTimeout <= 0 ||
		m.lastUserInputAt.IsZero() {
		return nil
	}

	m.localIdleGeneration++
	m.localIdleDueAt = m.lastUserInputAt.Add(m.effectiveSessionTimeout)
	return localIdleTickCmd(m.localIdleGeneration, m.localIdleDueAt)
}

func (m *Model) handleLocalIdleTick(msg localIdleTickMsg) tea.Cmd {
	if msg.Generation != m.localIdleGeneration || !msg.DueAt.Equal(m.localIdleDueAt) {
		return nil
	}
	if !m.canTrackLocalIdle() || m.localIdleDisconnectSent {
		return nil
	}

	now := time.Now()
	if !m.isLocallyIdle(now) {
		return m.armLocalIdleTimer()
	}

	m.localIdleDisconnectSent = true
	return m.disconnectForLocalIdleCmd()
}

func localIdleTickCmd(generation uint64, dueAt time.Time) tea.Cmd {
	return tea.Tick(tickDelay(dueAt), func(time.Time) tea.Msg {
		return localIdleTickMsg{Generation: generation, DueAt: dueAt}
	})
}

func (m Model) isLocallyIdle(now time.Time) bool {
	if m.effectiveSessionTimeout <= 0 || m.lastUserInputAt.IsZero() {
		return false
	}
	return !now.Before(m.lastUserInputAt.Add(m.effectiveSessionTimeout))
}

func (m *Model) handleManualLockFailed(errText string) tea.Cmd {
	m.manualLockPending = false
	if errText == "" {
		errText = "request failed"
	}
	m.lastError = "Lock failed: " + errText
	if m.viewState == ViewLockConfirm {
		m.viewState = m.lockConfirmReturnView()
	}
	return nil
}

func (m Model) lockConfirmReturnView() ViewState {
	if m.manualLockReturnView == ViewAuth || m.manualLockReturnView == ViewUnlock || m.manualLockReturnView == ViewLockConfirm {
		return ViewKeyList
	}
	return m.manualLockReturnView
}

func tickDelay(dueAt time.Time) time.Duration {
	delay := time.Until(dueAt)
	if delay <= 0 {
		return time.Nanosecond
	}
	return delay
}

func (m Model) disconnectForLocalIdleCmd() tea.Cmd {
	client := m.adminClient
	return func() tea.Msg {
		if client != nil {
			client.Disconnect()
		}
		return localIdleDisconnectedMsg{Reason: localIdleDisconnectReason}
	}
}

func (m Model) sendLockIdentityCmd(reason string) tea.Cmd {
	client := m.adminClient
	return func() tea.Msg {
		if client == nil {
			return lockIdentitySendFailedMsg{Error: fmt.Errorf("not connected")}
		}
		if err := client.SendLockIdentity(reason); err != nil {
			return lockIdentitySendFailedMsg{Error: err}
		}
		return nil
	}
}
