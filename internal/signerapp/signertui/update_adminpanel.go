// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	tea "github.com/charmbracelet/bubbletea"
)

// handleAdminPanelKeys handles keyboard input on the admin panel screen.
func (m Model) handleAdminPanelKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.adminRows()

	// Handle editing mode
	if m.admin.editingRow >= 0 {
		switch msg.String() {
		case "esc":
			m.admin.editingRow = -1
			m.admin.editValue = ""
		case "enter":
			// Submit the edit
			if m.admin.editingRow < len(rows) {
				row := rows[m.admin.editingRow]
				value := strings.TrimSpace(m.admin.editValue)
				m.admin.editingRow = -1
				if err := validateAdminSettingValue(row.key, value); err != nil {
					m.lastError = err.Error()
					return m, nil
				}
				return m, m.sendUpdateAdminSettingCmd(row.key, value)
			}
			m.admin.editingRow = -1
		case "backspace":
			if len(m.admin.editValue) > 0 {
				m.admin.editValue = m.admin.editValue[:len(m.admin.editValue)-1]
			}
		default:
			if len(msg.String()) == 1 {
				m.admin.editValue += msg.String()
			}
		}
		return m, nil
	}

	// Normal navigation mode
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewKeyList
		return m, nil

	case "k", "K":
		m.library.selectedTemplate = 0
		m.library.scrollOffset = 0
		m.library.installError = ""
		m.library.installStatus = ""
		m.library.pendingTemplate = nil
		m.viewState = ViewTemplateLibrary
		return m, tea.Batch(m.sendListLibraryTemplatesCmd(), m.waitForMessageCmd())

	case "p", "P":
		return m.openPolicyViewer()

	case "up":
		if m.admin.selectedRow > 0 {
			m.admin.selectedRow--
		}

	case "down", "j":
		if m.admin.selectedRow < len(rows)-1 {
			m.admin.selectedRow++
		}

	case "t", "T":
		// Revoke API token
		m.admin.revokeTokenFocus = 0 // Default to Cancel
		m.viewState = ViewRevokeTokenConfirm

	case "l":
		return m.openManualLockConfirm()

	case "enter":
		if m.admin.selectedRow < len(rows) {
			row := rows[m.admin.selectedRow]
			if row.action == "open_templates" {
				m.library.selectedTemplate = 0
				m.library.scrollOffset = 0
				m.library.installError = ""
				m.library.installStatus = ""
				m.library.pendingTemplate = nil
				m.viewState = ViewTemplateLibrary
				return m, tea.Batch(m.sendListLibraryTemplatesCmd(), m.waitForMessageCmd())
			}
			if row.action == "open_backup" {
				return m.openBackupConfirm()
			}
			if row.action == "open_restore" {
				return m.openRestoreList()
			}
			if row.action == "open_policy" {
				return m.openPolicyViewer()
			}
			if !row.editable {
				return m, nil
			}
			if row.isBool {
				// Toggle boolean
				newValue := "true"
				if row.value == "true" {
					newValue = "false"
				}
				return m, m.sendUpdateAdminSettingCmd(row.key, newValue)
			}
			if row.choices != nil {
				// Cycle to next choice
				return m, m.sendUpdateAdminSettingCmd(row.key, nextChoice(row.value, row.choices))
			}
			// Start editing text value
			m.admin.editingRow = m.admin.selectedRow
			m.admin.editValue = row.value
		}
	}

	return m, nil
}

func validateAdminSettingValue(key, value string) error {
	switch key {
	case adminproto.AdminSettingPassphraseTimeout:
		_, err := serverconfig.ParsePassphraseTimeout(value)
		return err
	default:
		return nil
	}
}
