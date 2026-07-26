// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) openRestoreList() (tea.Model, tea.Cmd) {
	m.resetRestoreFlow(true)
	m.viewState = ViewRestoreList
	return m, tea.Batch(m.sendListBackupsCmd(), m.waitForMessageCmd())
}

func (m Model) handleRestoreListKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.resetRestoreFlow(true)
		m.viewState = ViewKeyList
		return m, nil
	case "r", "R":
		m.restore.backupsLoaded = false
		m.restore.backups = nil
		return m, tea.Batch(m.sendListBackupsCmd(), m.waitForMessageCmd())
	case "up", "k":
		if m.restore.selectedBackup > 0 {
			m.restore.selectedBackup--
		}
	case "down", "j":
		if m.restore.selectedBackup < len(m.restore.backups)-1 {
			m.restore.selectedBackup++
		}
	case "enter":
		backupInfo, ok := m.currentRestoreBackup()
		if !ok {
			return m, nil
		}
		m.clearRestorePassphrase()
		m.restore.archivePath = backupInfo.Path
		m.restore.passphraseError = ""
		m.restore.previewError = ""
		m.restore.previewKeys = nil
		m.restore.previewErrors = nil
		m.restore.selected = nil
		m.restore.selectedKey = 0
		m.restore.previewScrollOffset = 0
		m.restore.overwrite = false
		m.viewState = ViewRestorePassphrase
	}
	return m, nil
}

func (m Model) handleRestorePassphraseKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.restore.previewing {
		if msg.String() == "esc" {
			m.lastError = "Preview in progress; wait for completion"
		}
		return m, nil
	}

	switch msg.String() {
	case "esc":
		m.clearRestorePassphrase()
		m.restore.passphraseError = ""
		m.viewState = ViewRestoreList
		return m, nil
	case "enter":
		if len(m.restore.passphrase) == 0 {
			m.restore.passphraseError = "Please enter the backup export passphrase"
			return m, nil
		}
		if m.restore.archivePath == "" {
			m.restore.passphraseError = "Please select a backup archive"
			return m, nil
		}
		m.restore.passphraseError = ""
		m.restore.previewing = true
		return m, tea.Batch(m.sendPreviewRestoreCmd(m.restore.archivePath, m.restore.passphrase), m.waitForMessageCmd())
	case "backspace":
		if len(m.restore.passphrase) > 0 {
			m.restore.passphrase[len(m.restore.passphrase)-1] = 0
			m.restore.passphrase = m.restore.passphrase[:len(m.restore.passphrase)-1]
			m.restore.passphraseError = ""
		}
		return m, nil
	default:
		if len(msg.String()) == 1 {
			m.restore.passphrase = append(m.restore.passphrase, msg.String()...)
			m.restore.passphraseError = ""
		}
	}
	return m, nil
}

func (m Model) handleRestorePreviewKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.clearRestorePassphrase()
		m.restore.previewError = ""
		m.viewState = ViewRestoreList
		return m, nil
	case "up", "k":
		if m.restore.previewFocus != restoreFocusList {
			return m, nil
		}
		if m.restore.selectedKey > 0 {
			m.restore.selectedKey--
			if m.restore.selectedKey < m.restore.previewScrollOffset {
				m.restore.previewScrollOffset = m.restore.selectedKey
			}
		}
	case "down", "j":
		if m.restore.previewFocus != restoreFocusList {
			return m, nil
		}
		if m.restore.selectedKey < len(m.restore.previewKeys)-1 {
			m.restore.selectedKey++
			visibleHeight := m.restorePreviewVisibleHeight()
			if m.restore.selectedKey >= m.restore.previewScrollOffset+visibleHeight {
				m.restore.previewScrollOffset = m.restore.selectedKey - visibleHeight + 1
			}
		}
	case " ":
		if len(m.restore.previewKeys) == 0 {
			return m, nil
		}
		key := m.restore.previewKeys[m.restore.selectedKey]
		if !m.restoreKeySelectable(key) {
			if key.AlreadyExists && !m.restore.overwrite {
				m.restore.previewError = "Enable overwrite before selecting existing keys"
			}
			return m, nil
		}
		if m.restore.selected == nil {
			m.restore.selected = make(map[string]bool)
		}
		m.restore.selected[key.Address] = !m.restore.selected[key.Address]
		if !m.restore.selected[key.Address] {
			delete(m.restore.selected, key.Address)
		}
		m.restore.previewError = ""
	case "a", "A":
		m.restore.selected = make(map[string]bool)
		for _, key := range m.restore.previewKeys {
			if m.restoreKeySelectable(key) {
				m.restore.selected[key.Address] = true
			}
		}
		m.restore.previewError = ""
	case "o", "O":
		m.restore.overwrite = !m.restore.overwrite
		if !m.restore.overwrite {
			for _, key := range m.restore.previewKeys {
				if key.AlreadyExists {
					delete(m.restore.selected, key.Address)
				}
			}
		}
		m.restore.previewError = ""
	case "tab", "shift+tab":
		if m.restore.previewFocus == restoreFocusList {
			m.restore.previewFocus = restoreFocusAction
		} else {
			m.restore.previewFocus = restoreFocusList
		}
		m.restore.previewError = ""
	case "enter":
		// Enter commits only from the Recover button, so arrowing through the
		// key list cannot start a recovery by reflex.
		if m.restore.previewFocus != restoreFocusAction {
			return m, nil
		}
		addresses := m.selectedRestoreAddresses()
		if len(addresses) == 0 {
			m.restore.previewError = "Select at least one key to restore"
			return m, nil
		}
		for _, key := range m.restore.previewKeys {
			if m.restore.selected[key.Address] && key.AlreadyExists && !m.restore.overwrite {
				m.restore.previewError = "Enable overwrite before restoring existing keys"
				return m, nil
			}
		}
		restoreCmd := m.sendRecoverBackupCmd(m.restore.archivePath, addresses, m.restore.passphrase)
		m.clearRestorePassphrase()
		m.restore.previewError = ""
		m.viewState = ViewRestoring
		return m, tea.Batch(restoreCmd, m.waitForMessageCmd())
	}
	return m, nil
}

func (m Model) handleRestoreReviewKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	requiresUnattended := recoveredUnattendedSigningAckRequired(m.restore.review)
	switch msg.String() {
	case "q", "esc":
		m.restore.previewError = fmt.Sprintf(
			"Recovered batch %s remains inactive",
			m.restore.restoreID,
		)
		m.viewState = ViewRestorePreview
	case "tab", "shift+tab", "up", "k", "down", "j":
		if !requiresUnattended {
			return m, nil
		}
		if m.restore.reviewFocus == restoreFocusList {
			m.restore.reviewFocus = restoreFocusAction
		} else {
			m.restore.reviewFocus = restoreFocusList
		}
		m.restore.previewError = ""
	case " ":
		if requiresUnattended && m.restore.reviewFocus == restoreFocusList {
			m.restore.unattendedAcknowledged = !m.restore.unattendedAcknowledged
			m.restore.previewError = ""
		}
	case "enter":
		// Enter commits only from the Activate button.
		if m.restore.reviewFocus != restoreFocusAction {
			return m, nil
		}
		if requiresUnattended && !m.restore.unattendedAcknowledged {
			m.restore.previewError = "Acknowledge unattended signing before activation"
			return m, nil
		}
		m.restore.previewError = ""
		m.viewState = ViewRestoring
		return m, tea.Batch(
			m.sendActivateRecoveredCmd(
				m.restore.restoreID,
				m.restore.review.ReviewToken,
				m.restore.unattendedAcknowledged,
				m.restore.overwrite,
			),
			m.waitForMessageCmd(),
		)
	}
	return m, nil
}

func recoveredUnattendedSigningAckRequired(
	review ReviewRecoveredResultMessage,
) bool {
	if review.UnattendedSigningAckRequired == nil {
		return review.DestinationApprovalMode == "auto_approve_fallback"
	}
	return *review.UnattendedSigningAckRequired
}

func (m Model) handleRestoreDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up":
		if m.restore.displaySelectedKey > 0 {
			m.restore.displaySelectedKey--
		}
	case "down":
		if m.restore.displaySelectedKey < len(m.restore.result.Activated)-1 {
			m.restore.displaySelectedKey++
		}
	case "q", "esc", "enter", " ":
		result := m.restore.result
		m.resetRestoreFlow(true)
		if len(result.Activated) > 0 {
			m.selectKeyByAddress(result.Activated[0].Address)
		}
		m.viewState = ViewKeyList
		return m, tea.Batch(m.sendListKeysCmd(), m.waitForMessageCmd())
	}
	return m, nil
}
