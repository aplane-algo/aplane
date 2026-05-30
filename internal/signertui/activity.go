// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

const (
	activityReportInterval     = 30 * time.Second
	localIdleLockReason        = "apadmin local inactivity timeout"
	manualLockReason           = "apadmin manual lock"
	localIdleLockRetryInitial  = time.Second
	localIdleLockRetryMaxDelay = 30 * time.Second
)

func (m Model) recordUserActivity(now time.Time, msg tea.KeyMsg) (Model, tea.Cmd) {
	if !m.shouldTrackUserActivity(msg) {
		return m, nil
	}

	m.lastUserInputAt = now
	m.activityReportPending = true
	m.localIdleLockSent = false
	m.localIdleLockRetryAt = time.Time{}
	m.localIdleLockRetryDelay = 0

	return m, tea.Batch(
		m.scheduleActivityReport(now),
		m.armLocalIdleTimer(),
	)
}

func (m Model) shouldTrackUserActivity(msg tea.KeyMsg) bool {
	if !m.canSendActivitySignals() {
		return false
	}
	if m.viewState == ViewSigningPopup && isSignResponseKey(msg) {
		return false
	}
	return true
}

func isSignResponseKey(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "enter", " ", "y", "a", "n", "r", "esc":
		return true
	default:
		return false
	}
}

func (m Model) canSendActivitySignals() bool {
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
	m.lastActivityReportAt = time.Time{}
	m.activityReportPending = false
	m.activityReportArmed = false
	m.activityReportDueAt = time.Time{}
	m.activityReportGeneration++
	m.localIdleLockSent = false
	m.localIdleLockRetryDelay = 0
	m.localIdleLockRetryAt = time.Time{}
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
	timeout, err := apconfig.ParsePassphraseTimeout(settings.PassphraseTimeout)
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

func (m *Model) scheduleActivityReport(now time.Time) tea.Cmd {
	if !m.canSendActivitySignals() || !m.activityReportPending {
		return nil
	}

	if m.lastActivityReportAt.IsZero() || now.Sub(m.lastActivityReportAt) >= activityReportInterval {
		return m.sendActivityReport(now)
	}

	if m.activityReportArmed {
		return nil
	}

	m.activityReportGeneration++
	m.activityReportDueAt = m.lastActivityReportAt.Add(activityReportInterval)
	m.activityReportArmed = true
	return activityReportTickCmd(m.activityReportGeneration, m.activityReportDueAt)
}

func (m *Model) handleActivityReportTick(msg activityReportTickMsg) tea.Cmd {
	if !m.activityReportArmed ||
		msg.Generation != m.activityReportGeneration ||
		!msg.DueAt.Equal(m.activityReportDueAt) {
		return nil
	}
	m.activityReportArmed = false

	if !m.canSendActivitySignals() || !m.activityReportPending {
		return nil
	}
	if !m.lastActivityReportAt.IsZero() && !m.lastUserInputAt.After(m.lastActivityReportAt) {
		m.activityReportPending = false
		return nil
	}

	now := time.Now()
	if !m.lastActivityReportAt.IsZero() && now.Sub(m.lastActivityReportAt) < activityReportInterval {
		return m.scheduleActivityReport(now)
	}
	return m.sendActivityReport(now)
}

func (m *Model) sendActivityReport(now time.Time) tea.Cmd {
	m.lastActivityReportAt = now
	m.activityReportPending = false
	m.activityReportArmed = false
	m.activityReportDueAt = time.Time{}
	m.activityReportGeneration++
	return m.sendAdminActivityCmd()
}

func activityReportTickCmd(generation uint64, dueAt time.Time) tea.Cmd {
	return tea.Tick(tickDelay(dueAt), func(time.Time) tea.Msg {
		return activityReportTickMsg{Generation: generation, DueAt: dueAt}
	})
}

func (m *Model) armLocalIdleTimer() tea.Cmd {
	if !m.canSendActivitySignals() ||
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
	if !m.canSendActivitySignals() || m.localIdleLockSent {
		return nil
	}

	now := time.Now()
	if !m.isLocallyIdle(now) {
		return m.armLocalIdleTimer()
	}

	m.localIdleLockSent = true
	return m.sendLockIdentityCmd(localIdleLockReason)
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

func (m *Model) handleLockIdentityFailed(errText string) tea.Cmd {
	m.localIdleLockSent = false
	if errText != "" {
		m.lastError = "Local idle lock failed: " + errText
	}
	return m.scheduleLocalIdleLockRetry(time.Now())
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

func (m *Model) scheduleLocalIdleLockRetry(now time.Time) tea.Cmd {
	if !m.canSendActivitySignals() || !m.isLocallyIdle(now) {
		return nil
	}

	delay := m.localIdleLockRetryDelay
	if delay <= 0 {
		delay = localIdleLockRetryInitial
	} else {
		delay *= 2
		if delay > localIdleLockRetryMaxDelay {
			delay = localIdleLockRetryMaxDelay
		}
	}
	m.localIdleLockRetryDelay = delay
	m.localIdleLockRetryAt = now.Add(delay)
	return localIdleLockRetryTickCmd(m.localIdleLockRetryAt)
}

func (m *Model) handleLocalIdleLockRetryTick(msg localIdleLockRetryTickMsg) tea.Cmd {
	if m.localIdleLockRetryAt.IsZero() || !msg.DueAt.Equal(m.localIdleLockRetryAt) {
		return nil
	}
	m.localIdleLockRetryAt = time.Time{}

	if !m.canSendActivitySignals() || m.localIdleLockSent || !m.isLocallyIdle(time.Now()) {
		return nil
	}

	m.localIdleLockSent = true
	return m.sendLockIdentityCmd(localIdleLockReason)
}

func localIdleLockRetryTickCmd(dueAt time.Time) tea.Cmd {
	return tea.Tick(tickDelay(dueAt), func(time.Time) tea.Msg {
		return localIdleLockRetryTickMsg{DueAt: dueAt}
	})
}

func tickDelay(dueAt time.Time) time.Duration {
	delay := time.Until(dueAt)
	if delay <= 0 {
		return time.Nanosecond
	}
	return delay
}

func (m Model) sendAdminActivityCmd() tea.Cmd {
	client := m.adminClient
	return func() tea.Msg {
		if client == nil {
			return adminActivitySendFailedMsg{Error: fmt.Errorf("not connected")}
		}
		if err := client.SendAdminActivity(); err != nil {
			return adminActivitySendFailedMsg{Error: err}
		}
		return nil
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
