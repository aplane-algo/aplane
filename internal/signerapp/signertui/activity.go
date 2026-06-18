// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	localIdleDisconnectReason             = "apadmin disconnected after inactivity timeout"
	manualLockReason                      = "apadmin manual lock"
	invalidPassphraseTimeoutWarningPrefix = "Invalid passphrase timeout from server: "
)

func (m Model) recordUserActivity(now time.Time, msg tea.KeyMsg) (Model, tea.Cmd) {
	if !m.shouldTrackLocalIdle(msg) {
		return m, nil
	}

	m.activity.lastInputAt = now
	m.activity.idleDisconnectSent = false

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
	m.activity.lastInputAt = time.Time{}
	m.activity.idleDisconnectSent = false
	m.activity.idleGeneration++
	m.activity.idleDueAt = time.Time{}
}

func (m *Model) applySignerLockedState() {
	m.clearRestorePassphrase()
	m.manualLock.pending = false
	m.manualLock.focus = 0
	m.manualLock.returnView = ViewKeyList
	m.signerLocked = true
	m.signerStatusKnown = true
	m.viewState = ViewUnlock
	m.auth.passphraseInput = ""
	m.auth.passphraseError = ""
	m.resetActivityState()
}

func (m *Model) applySignerUnlockedState(keyCount int) {
	m.manualLock.pending = false
	m.manualLock.focus = 0
	m.manualLock.returnView = ViewKeyList
	m.signerLocked = false
	m.signerStatusKnown = true
	m.keyCount = keyCount
	m.viewState = ViewKeyList
	m.resetActivityState()
	m.activity.lastInputAt = time.Now()
}

func (m *Model) applyAdminSettingsTimeout(settings AdminSettings) tea.Cmd {
	timeout, err := serverconfig.ParsePassphraseTimeout(settings.PassphraseTimeout)
	if err != nil {
		m.activity.sessionTimeout = 0
		m.activity.idleGeneration++
		m.activity.idleDueAt = time.Time{}
		m.setPersistentWarning(invalidPassphraseTimeoutWarningPrefix + err.Error())
		return nil
	}

	if strings.HasPrefix(m.lastWarning, invalidPassphraseTimeoutWarningPrefix) {
		m.clearWarning()
	}

	if timeout == m.activity.sessionTimeout {
		if m.activity.idleDueAt.IsZero() {
			return m.armLocalIdleTimer()
		}
		return nil
	}
	m.activity.sessionTimeout = timeout
	return m.armLocalIdleTimer()
}

func (m *Model) armLocalIdleTimer() tea.Cmd {
	if !m.canTrackLocalIdle() ||
		m.activity.sessionTimeout <= 0 ||
		m.activity.lastInputAt.IsZero() {
		return nil
	}

	m.activity.idleGeneration++
	m.activity.idleDueAt = m.activity.lastInputAt.Add(m.activity.sessionTimeout)
	return localIdleTickCmd(m.activity.idleGeneration, m.activity.idleDueAt)
}

func (m *Model) handleLocalIdleTick(msg localIdleTickMsg) tea.Cmd {
	if msg.Generation != m.activity.idleGeneration || !msg.DueAt.Equal(m.activity.idleDueAt) {
		return nil
	}
	if !m.canTrackLocalIdle() || m.activity.idleDisconnectSent {
		return nil
	}

	now := time.Now()
	if !m.isLocallyIdle(now) {
		return m.armLocalIdleTimer()
	}

	m.activity.idleDisconnectSent = true
	return m.disconnectForLocalIdleCmd()
}

func localIdleTickCmd(generation uint64, dueAt time.Time) tea.Cmd {
	return tea.Tick(tickDelay(dueAt), func(time.Time) tea.Msg {
		return localIdleTickMsg{Generation: generation, DueAt: dueAt}
	})
}

func (m Model) isLocallyIdle(now time.Time) bool {
	if m.activity.sessionTimeout <= 0 || m.activity.lastInputAt.IsZero() {
		return false
	}
	return !now.Before(m.activity.lastInputAt.Add(m.activity.sessionTimeout))
}

func (m *Model) handleManualLockFailed(errText string) tea.Cmd {
	m.manualLock.pending = false
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
	if m.manualLock.returnView == ViewAuth || m.manualLock.returnView == ViewUnlock || m.manualLock.returnView == ViewLockConfirm {
		return ViewKeyList
	}
	return m.manualLock.returnView
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
