// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	tea "github.com/charmbracelet/bubbletea"
)

// handleAdminPanelKeys handles keyboard input on the admin panel screen.
func (m Model) handleAdminPanelKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.adminRows()

	// Handle editing mode
	if m.adminEditingRow >= 0 {
		switch msg.String() {
		case "esc":
			m.adminEditingRow = -1
			m.adminEditValue = ""
		case "enter":
			// Submit the edit
			if m.adminEditingRow < len(rows) {
				row := rows[m.adminEditingRow]
				value := strings.TrimSpace(m.adminEditValue)
				m.adminEditingRow = -1
				if err := validateAdminSettingValue(row.key, value); err != nil {
					m.lastError = err.Error()
					return m, nil
				}
				return m, m.sendUpdateAdminSettingCmd(row.key, value)
			}
			m.adminEditingRow = -1
		case "backspace":
			if len(m.adminEditValue) > 0 {
				m.adminEditValue = m.adminEditValue[:len(m.adminEditValue)-1]
			}
		default:
			if len(msg.String()) == 1 {
				m.adminEditValue += msg.String()
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
		m.selectedTemplate = 0
		m.templateScrollOffset = 0
		m.templateInstallError = ""
		m.templateInstallStatus = ""
		m.pendingTemplate = nil
		m.viewState = ViewTemplateLibrary
		return m, tea.Batch(m.sendListLibraryTemplatesCmd(), m.waitForMessageCmd())

	case "p", "P":
		return m.openPolicyViewer()

	case "up":
		if m.adminSelectedRow > 0 {
			m.adminSelectedRow--
		}

	case "down", "j":
		if m.adminSelectedRow < len(rows)-1 {
			m.adminSelectedRow++
		}

	case "t", "T":
		// Revoke API token
		m.revokeTokenConfirmFocus = 0 // Default to Cancel
		m.viewState = ViewRevokeTokenConfirm

	case "l":
		return m.openManualLockConfirm()

	case "enter":
		if m.adminSelectedRow < len(rows) {
			row := rows[m.adminSelectedRow]
			if row.action == "open_templates" {
				m.selectedTemplate = 0
				m.templateScrollOffset = 0
				m.templateInstallError = ""
				m.templateInstallStatus = ""
				m.pendingTemplate = nil
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
			m.adminEditingRow = m.adminSelectedRow
			m.adminEditValue = row.value
		}
	}

	return m, nil
}

func validateAdminSettingValue(key, value string) error {
	switch key {
	case adminproto.AdminSettingPassphraseTimeout:
		_, err := apconfig.ParsePassphraseTimeout(value)
		return err
	case adminproto.AdminSettingEndpointAdvertiseURL:
		value = strings.TrimRight(strings.TrimSpace(value), "/")
		if value == "" {
			return nil
		}
		return endpointrefs.ValidatePortableURL(value)
	default:
		return nil
	}
}
