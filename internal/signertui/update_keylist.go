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
	if m.filterActive {
		switch msg.String() {
		case "esc":
			// Clear filter and exit filter mode
			m.filterInput = ""
			m.filterActive = false
			m.resetKeyListSelection()
		case "enter":
			// Keep filter, exit filter mode
			m.filterActive = false
			m.resetKeyListSelection()
		case "backspace":
			if len(m.filterInput) > 0 {
				m.filterInput = m.filterInput[:len(m.filterInput)-1]
				m.resetKeyListSelection()
			}
		default:
			if len(msg.String()) == 1 {
				m.filterInput += msg.String()
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
		if m.filterInput != "" {
			m.filterInput = ""
			m.resetKeyListSelection()
		}
		return m, nil

	case "/":
		// Activate filter mode
		m.filterActive = true
		return m, nil

	}

	// Get filtered keys for navigation and operations
	displayKeys := m.filteredKeys()

	switch msg.String() {
	case "up", "k":
		if m.selectedKey > 0 {
			m.selectedKey--
			// Scroll up if selected key is above visible area
			if m.selectedKey < m.scrollOffset {
				m.scrollOffset = m.selectedKey
			}
		}

	case "down", "j":
		if m.selectedKey < len(displayKeys)-1 {
			m.selectedKey++
			// Scroll down if selected key is below visible area
			visibleHeight := m.keyListVisibleHeight()
			if m.selectedKey >= m.scrollOffset+visibleHeight {
				m.scrollOffset = m.selectedKey - visibleHeight + 1
			}
		}

	case "g":
		// Generate new key
		m.generateFocus = 0 // Start on key type selection
		m.generateKeyType = 0
		m.generateError = ""
		m.generateParamScrollOffset = 0 // Reset scroll
		m.viewState = ViewGenerateForm
		return m, tea.Batch(m.sendListKeyTypesCmd(), m.sendListLibraryTemplatesCmd(), m.waitForMessageCmd())

	case "i":
		// Import key
		m.importFocus = 0 // Start on key type selection
		m.importKeyType = 0
		m.importMnemonicInput.SetValue("")
		m.importMnemonicInput.Blur()
		m.importError = ""
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
		m.adminSelectedRow = 0
		m.adminEditingRow = -1
		m.adminEditValue = ""
		m.viewState = ViewAdminPanel
		return m, tea.Batch(m.sendGetAdminSettingsCmd(), m.waitForMessageCmd(), adminRefreshTickCmd())

	case "enter":
		// Show key details
		if len(displayKeys) > 0 && m.selectedKey < len(displayKeys) {
			return m, tea.Batch(m.sendGetKeyDetailsCmd(displayKeys[m.selectedKey].Address), m.waitForMessageCmd())
		}
	}

	return m, nil
}

func (m *Model) resetKeyListSelection() {
	m.selectedKey = 0
	m.scrollOffset = 0
}

func (m Model) openBackupConfirm() (tea.Model, tea.Cmd) {
	m.backupExportPassphrase = ""
	m.backupConfirmPassphrase = ""
	m.backupConfirmError = ""
	m.backupConfirmFocus = 0
	m.viewState = ViewBackupConfirm
	return m, nil
}

// handleKeyDetailsKeys handles keyboard input on key details screen
func (m Model) handleKeyDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", " ", "q":
		m.viewState = ViewKeyList
		m.detailsScrollOffset = 0 // Reset scroll on close
		m.detailsSaveStatus = ""
		return m, nil

	case "s":
		// Save TEAL to file (only if TEAL is available)
		if m.detailsTEAL != "" && m.dataDir != "" {
			_, err := saveTEALToFile(m.dataDir, m.detailsAddress, m.detailsTEAL)
			if err != nil {
				m.detailsSaveStatus = fmt.Sprintf("Save failed: %v", err)
			} else {
				m.detailsSaveStatus = fmt.Sprintf("Saved to files/%s.teal", m.detailsAddress)
			}
		}
		return m, nil

	case "t":
		if m.detailsTEAL != "" {
			m.detailsScrollOffset = 0
			m.viewState = ViewTEALFullDisplay
		}
		return m, nil

	case "d":
		// Delete selected key - show confirmation dialog
		m.deleteAddress = m.detailsAddress
		m.deleteKeyType = m.detailsKeyType
		m.deleteConfirmFocus = 0 // Default to Cancel (safer)
		m.viewState = ViewDeleteConfirm
		return m, nil

	case "up", "k":
		// Scroll up
		if m.detailsScrollOffset > 0 {
			m.detailsScrollOffset--
		}
		return m, nil

	case "down", "j":
		// Scroll down - calculate max offset based on content
		maxVisibleLines := m.detailsVisibleLines()
		// Parameters: count rendered lines so multi-line address lists scroll correctly.
		itemCount := len(buildDetailsParameterLines(m.detailsKeyType, m.detailsParameters))
		visibleItems := maxVisibleLines

		maxOffset := itemCount - visibleItems
		if maxOffset < 0 {
			maxOffset = 0
		}
		if m.detailsScrollOffset < maxOffset {
			m.detailsScrollOffset++
		}
		return m, nil
	}
	return m, nil
}

func (m Model) handleTEALFullDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewKeyDetails
		m.detailsScrollOffset = 0
		return m, nil
	case "up", "k":
		if m.detailsScrollOffset > 0 {
			m.detailsScrollOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := len(strings.Split(m.detailsTEAL, "\n")) - m.tealFullDisplayVisibleLines()
		if maxOffset < 0 {
			maxOffset = 0
		}
		if m.detailsScrollOffset < maxOffset {
			m.detailsScrollOffset++
		}
		return m, nil
	case "pgup":
		visible := m.tealFullDisplayVisibleLines()
		m.detailsScrollOffset -= visible
		if m.detailsScrollOffset < 0 {
			m.detailsScrollOffset = 0
		}
		return m, nil
	case "pgdown":
		visible := m.tealFullDisplayVisibleLines()
		maxOffset := len(strings.Split(m.detailsTEAL, "\n")) - visible
		if maxOffset < 0 {
			maxOffset = 0
		}
		m.detailsScrollOffset += visible
		if m.detailsScrollOffset > maxOffset {
			m.detailsScrollOffset = maxOffset
		}
		return m, nil
	}
	return m, nil
}
