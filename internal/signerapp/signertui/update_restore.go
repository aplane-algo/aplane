// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import tea "github.com/charmbracelet/bubbletea"

func (m Model) openRestoreList() (tea.Model, tea.Cmd) {
	fromRecovery := m.signerState == signerRuntimeRecovery || m.viewState == ViewStoreRecovery
	m.resetRestoreFlow(true)
	m.restore.returnToRecovery = fromRecovery
	m.viewState = ViewRestoreList
	return m, tea.Batch(m.sendListBackupsCmd(), m.waitForMessageCmd())
}

func (m Model) handleRestoreListKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		if m.restore.returnToRecovery || m.signerState == signerRuntimeRecovery {
			m.resetRestoreFlow(true)
			return m.openStoreRecovery()
		}
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
		m.restore.replaceExisting = false
		m.restore.replaceConflicts = nil
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
		if m.restore.replaceExisting {
			addresses := m.selectedRestoreAddresses()
			if len(addresses) == 0 {
				m.restore.passphraseError = "No conflicting credentials are selected"
				return m, nil
			}
			restoreCmd := m.sendRestoreBackupCmd(
				m.restore.archivePath, addresses, m.restore.passphrase, true,
			)
			m.clearRestorePassphrase()
			m.restore.passphraseError = ""
			m.restore.progressLabel = "Replacing Conflicting Credentials"
			m.viewState = ViewRestoring
			return m, tea.Batch(restoreCmd, m.waitForMessageCmd())
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
		// Recovery is inactive and never overwrites anything: conflicting
		// keys are freely selectable, and the replace-existing consent is
		// collected on the restore confirmation beside the exact conflicts.
		if len(m.restore.previewKeys) == 0 {
			return m, nil
		}
		key := m.restore.previewKeys[m.restore.selectedKey]
		if !m.restoreKeySelectable(key) {
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
	case "tab", "shift+tab":
		if m.restore.previewFocus == restoreFocusList {
			m.restore.previewFocus = restoreFocusAction
		} else {
			m.restore.previewFocus = restoreFocusList
		}
		m.restore.previewError = ""
	case "enter":
		// Enter commits only from the Restore button, so arrowing through the
		// key list cannot start a restore by reflex.
		if m.restore.previewFocus != restoreFocusAction {
			return m, nil
		}
		addresses := m.selectedRestoreAddresses()
		if len(addresses) == 0 {
			m.restore.previewError = "Select at least one key to restore"
			return m, nil
		}
		if len(m.restore.passphrase) == 0 {
			// The passphrase is zeroed once recovery launches; a doomed
			// retry must not consume a restore rate-limiter slot.
			m.restore.previewError = "Export passphrase no longer available; press Esc and re-enter it"
			return m, nil
		}
		restoreCmd := m.sendRestoreBackupCmd(
			m.restore.archivePath, addresses, m.restore.passphrase, false,
		)
		m.clearRestorePassphrase()
		m.restore.previewError = ""
		m.restore.progressLabel = "Restoring Credentials"
		m.viewState = ViewRestoring
		return m, tea.Batch(restoreCmd, m.waitForMessageCmd())
	}
	return m, nil
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
		if m.signerState == signerRuntimeRecovery {
			// The daemon is still in recovery — even after a successful
			// restore, if the server-side recovery-exit rescan failed
			// no unlocked push is coming, and ordinary administration must
			// stay unavailable (ARCH_TUI). The blocking recovery screen is
			// the only valid destination.
			return m.openStoreRecovery()
		}
		m.resetRestoreFlow(true)
		if len(result.Activated) > 0 {
			m.selectKeyByAddress(result.Activated[0].Address)
		}
		m.viewState = ViewKeyList
		return m, tea.Batch(m.sendListKeysCmd(), m.waitForMessageCmd())
	}
	return m, nil
}
