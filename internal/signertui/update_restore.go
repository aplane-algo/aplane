// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import tea "github.com/charmbracelet/bubbletea"

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
		m.restoreBackupsLoaded = false
		m.restoreBackups = nil
		return m, tea.Batch(m.sendListBackupsCmd(), m.waitForMessageCmd())
	case "up", "k":
		if m.selectedBackup > 0 {
			m.selectedBackup--
		}
	case "down", "j":
		if m.selectedBackup < len(m.restoreBackups)-1 {
			m.selectedBackup++
		}
	case "enter":
		backupInfo, ok := m.currentRestoreBackup()
		if !ok {
			return m, nil
		}
		m.clearRestorePassphrase()
		m.restoreArchivePath = backupInfo.Path
		m.restorePassphraseError = ""
		m.restorePreviewError = ""
		m.restorePreviewKeys = nil
		m.restorePreviewErrors = nil
		m.restoreSelected = nil
		m.restoreSelectedKey = 0
		m.restorePreviewScrollOffset = 0
		m.restoreOverwrite = false
		m.viewState = ViewRestorePassphrase
	}
	return m, nil
}

func (m Model) handleRestorePassphraseKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.restorePreviewing {
		if msg.String() == "esc" {
			m.lastError = "Preview in progress; wait for completion"
		}
		return m, nil
	}

	switch msg.String() {
	case "esc":
		m.clearRestorePassphrase()
		m.restorePassphraseError = ""
		m.viewState = ViewRestoreList
		return m, nil
	case "enter":
		if len(m.restorePassphrase) == 0 {
			m.restorePassphraseError = "Please enter the backup export passphrase"
			return m, nil
		}
		if m.restoreArchivePath == "" {
			m.restorePassphraseError = "Please select a backup archive"
			return m, nil
		}
		m.restorePassphraseError = ""
		m.restorePreviewing = true
		return m, tea.Batch(m.sendPreviewRestoreCmd(m.restoreArchivePath, m.restorePassphrase), m.waitForMessageCmd())
	case "backspace":
		if len(m.restorePassphrase) > 0 {
			m.restorePassphrase[len(m.restorePassphrase)-1] = 0
			m.restorePassphrase = m.restorePassphrase[:len(m.restorePassphrase)-1]
			m.restorePassphraseError = ""
		}
		return m, nil
	default:
		if len(msg.String()) == 1 {
			m.restorePassphrase = append(m.restorePassphrase, msg.String()...)
			m.restorePassphraseError = ""
		}
	}
	return m, nil
}

func (m Model) handleRestorePreviewKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.clearRestorePassphrase()
		m.restorePreviewError = ""
		m.viewState = ViewRestoreList
		return m, nil
	case "up", "k":
		if m.restoreSelectedKey > 0 {
			m.restoreSelectedKey--
			if m.restoreSelectedKey < m.restorePreviewScrollOffset {
				m.restorePreviewScrollOffset = m.restoreSelectedKey
			}
		}
	case "down", "j":
		if m.restoreSelectedKey < len(m.restorePreviewKeys)-1 {
			m.restoreSelectedKey++
			visibleHeight := m.restorePreviewVisibleHeight()
			if m.restoreSelectedKey >= m.restorePreviewScrollOffset+visibleHeight {
				m.restorePreviewScrollOffset = m.restoreSelectedKey - visibleHeight + 1
			}
		}
	case " ":
		if len(m.restorePreviewKeys) == 0 {
			return m, nil
		}
		key := m.restorePreviewKeys[m.restoreSelectedKey]
		if !m.restoreKeySelectable(key) {
			if key.AlreadyExists && !m.restoreOverwrite {
				m.restorePreviewError = "Enable overwrite before selecting existing keys"
			}
			return m, nil
		}
		if m.restoreSelected == nil {
			m.restoreSelected = make(map[string]bool)
		}
		m.restoreSelected[key.Address] = !m.restoreSelected[key.Address]
		if !m.restoreSelected[key.Address] {
			delete(m.restoreSelected, key.Address)
		}
		m.restorePreviewError = ""
	case "a", "A":
		m.restoreSelected = make(map[string]bool)
		for _, key := range m.restorePreviewKeys {
			if m.restoreKeySelectable(key) {
				m.restoreSelected[key.Address] = true
			}
		}
		m.restorePreviewError = ""
	case "o", "O":
		m.restoreOverwrite = !m.restoreOverwrite
		if !m.restoreOverwrite {
			for _, key := range m.restorePreviewKeys {
				if key.AlreadyExists {
					delete(m.restoreSelected, key.Address)
				}
			}
		}
		m.restorePreviewError = ""
	case "enter":
		addresses := m.selectedRestoreAddresses()
		if len(addresses) == 0 {
			m.restorePreviewError = "Select at least one key to restore"
			return m, nil
		}
		for _, key := range m.restorePreviewKeys {
			if m.restoreSelected[key.Address] && key.AlreadyExists && !m.restoreOverwrite {
				m.restorePreviewError = "Enable overwrite before restoring existing keys"
				return m, nil
			}
		}
		restoreCmd := m.sendRestoreBackupCmd(m.restoreArchivePath, addresses, m.restoreOverwrite, m.restorePassphrase)
		m.clearRestorePassphrase()
		m.restorePreviewError = ""
		m.viewState = ViewRestoring
		return m, tea.Batch(restoreCmd, m.waitForMessageCmd())
	}
	return m, nil
}

func (m Model) handleRestoreDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up":
		if m.restoreDisplaySelectedKey > 0 {
			m.restoreDisplaySelectedKey--
		}
	case "down":
		if m.restoreDisplaySelectedKey < len(m.restoreResult.Restored)-1 {
			m.restoreDisplaySelectedKey++
		}
	case "q", "esc", "enter", " ":
		result := m.restoreResult
		m.resetRestoreFlow(true)
		if len(result.Restored) > 0 {
			m.selectKeyByAddress(result.Restored[0].Address)
		}
		m.viewState = ViewKeyList
		return m, tea.Batch(m.sendListKeysCmd(), m.waitForMessageCmd())
	}
	return m, nil
}
