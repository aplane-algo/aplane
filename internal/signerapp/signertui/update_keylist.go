// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/auth"

	tea "github.com/charmbracelet/bubbletea"
)

// saveTEALToFile saves TEAL source to a file in the data directory
func saveTEALToFile(dataDir, address, teal string) (string, error) {
	// Create files directory under the user directory
	filesDir := filepath.Join(dataDir, "identities", auth.CurrentProductIdentityID(), "files")
	if err := os.MkdirAll(filesDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create files directory: %w", err)
	}

	// Write TEAL to file
	filePath := filepath.Join(filesDir, address+".teal")
	if err := os.WriteFile(filePath, []byte(teal), 0640); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return filePath, nil
}

// handleKeyListKeys handles keyboard input on key list screen
func (m Model) handleKeyListKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle filter mode input
	if m.keylist.filterActive {
		switch msg.String() {
		case "esc":
			// Clear filter and exit filter mode
			m.keylist.filterInput = ""
			m.keylist.filterActive = false
			m.resetKeyListSelection()
		case "enter":
			// Keep filter, exit filter mode
			m.keylist.filterActive = false
			m.resetKeyListSelection()
		case "backspace":
			if len(m.keylist.filterInput) > 0 {
				m.keylist.filterInput = m.keylist.filterInput[:len(m.keylist.filterInput)-1]
				m.resetKeyListSelection()
			}
		default:
			if len(msg.String()) == 1 {
				m.keylist.filterInput += msg.String()
				m.resetKeyListSelection()
			}
		}
		return m, nil
	}

	switch msg.String() {
	case "q":
		m.quitting = true
		return m, tea.Quit

	case "esc":
		// Clear filter if active, otherwise do nothing (only q quits)
		if m.keylist.filterInput != "" {
			m.keylist.filterInput = ""
			m.resetKeyListSelection()
		}
		return m, nil

	case "/":
		// Activate filter mode
		m.keylist.filterActive = true
		return m, nil

	}

	// Get filtered keys for navigation and operations
	displayKeys := m.filteredKeys()

	switch msg.String() {
	case "up", "k":
		if m.keylist.selectedKey > 0 {
			m.keylist.selectedKey--
			// Scroll up if selected key is above visible area
			if m.keylist.selectedKey < m.keylist.scrollOffset {
				m.keylist.scrollOffset = m.keylist.selectedKey
			}
		}

	case "down", "j":
		if m.keylist.selectedKey < len(displayKeys)-1 {
			m.keylist.selectedKey++
			// Scroll down if selected key is below visible area
			visibleHeight := m.keyListVisibleHeight()
			if m.keylist.selectedKey >= m.keylist.scrollOffset+visibleHeight {
				m.keylist.scrollOffset = m.keylist.selectedKey - visibleHeight + 1
			}
		}

	case "g":
		// Generate new key
		m.forms.generateFocus = 0 // Start on key type selection
		m.forms.generateKeyType = 0
		m.forms.generateError = ""
		m.forms.generateParamScrollOffset = 0 // Reset scroll
		m.viewState = ViewGenerateForm
		return m, tea.Batch(m.sendListKeyTypesCmd(), m.sendListLibraryTemplatesCmd(), m.waitForMessageCmd())

	case "i":
		// Import key
		m.forms.importFocus = 0 // Start on key type selection
		m.forms.importKeyType = 0
		m.forms.importMnemonicInput.SetValue("")
		m.forms.importMnemonicInput.Blur()
		m.forms.importError = ""
		m.viewState = ViewImportForm

	case "b", "B":
		return m.openBackupConfirm()

	case "r", "R":
		return m.openRestoreList()

	case "p", "P":
		return m.openPolicyViewer()

	case "l":
		return m.openManualLockConfirm()

	case "s", "S":
		// Open settings panel
		m.admin.selectedRow = 0
		m.admin.editingRow = -1
		m.admin.editValue = ""
		m.viewState = ViewAdminPanel
		return m, tea.Batch(m.sendGetAdminSettingsCmd(), m.waitForMessageCmd(), adminRefreshTickCmd())

	case "enter":
		// Show key details
		if len(displayKeys) > 0 && m.keylist.selectedKey < len(displayKeys) {
			return m, tea.Batch(m.sendGetKeyDetailsCmd(displayKeys[m.keylist.selectedKey].Address), m.waitForMessageCmd())
		}
	}

	return m, nil
}

func (m *Model) resetKeyListSelection() {
	m.keylist.selectedKey = 0
	m.keylist.scrollOffset = 0
}

func (m Model) openBackupConfirm() (tea.Model, tea.Cmd) {
	m.backup.exportPassphrase = ""
	m.backup.confirmPassphrase = ""
	m.backup.confirmError = ""
	m.backup.confirmFocus = 0
	m.viewState = ViewBackupConfirm
	return m, nil
}

// handleKeyDetailsKeys handles keyboard input on key details screen
func (m Model) handleKeyDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", " ", "q":
		m.viewState = ViewKeyList
		m.details.scrollOffset = 0 // Reset scroll on close
		m.details.saveStatus = ""
		return m, nil

	case "s":
		// Save TEAL to file (only if TEAL is available)
		if m.details.teal != "" && m.dataDir != "" {
			_, err := saveTEALToFile(m.dataDir, m.details.address, m.details.teal)
			if err != nil {
				m.details.saveStatus = fmt.Sprintf("Save failed: %v", err)
			} else {
				m.details.saveStatus = fmt.Sprintf("Saved to files/%s.teal", m.details.address)
			}
		}
		return m, nil

	case "t":
		if m.details.teal != "" {
			m.details.scrollOffset = 0
			m.viewState = ViewTEALFullDisplay
		}
		return m, nil

	case "d":
		// Delete selected key - show confirmation dialog
		m.del.address = m.details.address
		m.del.keyType = m.details.keyType
		m.del.focus = 0 // Default to Cancel (safer)
		m.viewState = ViewDeleteConfirm
		return m, nil

	case "up", "k":
		// Scroll up
		if m.details.scrollOffset > 0 {
			m.details.scrollOffset--
		}
		return m, nil

	case "down", "j":
		// Scroll down - calculate max offset based on content
		maxVisibleLines := m.detailsVisibleLines()
		// Parameters: count rendered lines so multi-line address lists scroll correctly.
		itemCount := len(buildDetailsParameterLines(m.details.keyType, m.details.parameters))
		visibleItems := maxVisibleLines

		maxOffset := itemCount - visibleItems
		if maxOffset < 0 {
			maxOffset = 0
		}
		if m.details.scrollOffset < maxOffset {
			m.details.scrollOffset++
		}
		return m, nil
	}
	return m, nil
}

func (m Model) handleTEALFullDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewKeyDetails
		m.details.scrollOffset = 0
		return m, nil
	case "up", "k":
		if m.details.scrollOffset > 0 {
			m.details.scrollOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := len(strings.Split(m.details.teal, "\n")) - m.tealFullDisplayVisibleLines()
		if maxOffset < 0 {
			maxOffset = 0
		}
		if m.details.scrollOffset < maxOffset {
			m.details.scrollOffset++
		}
		return m, nil
	case "pgup":
		visible := m.tealFullDisplayVisibleLines()
		m.details.scrollOffset -= visible
		if m.details.scrollOffset < 0 {
			m.details.scrollOffset = 0
		}
		return m, nil
	case "pgdown":
		visible := m.tealFullDisplayVisibleLines()
		maxOffset := len(strings.Split(m.details.teal, "\n")) - visible
		if maxOffset < 0 {
			maxOffset = 0
		}
		m.details.scrollOffset += visible
		if m.details.scrollOffset > maxOffset {
			m.details.scrollOffset = maxOffset
		}
		return m, nil
	}
	return m, nil
}
