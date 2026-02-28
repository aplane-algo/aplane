// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ViewerClosedMsg is sent when the external viewer (less) exits
type ViewerClosedMsg struct{}

// saveTEALToFile saves TEAL source to a file in the data directory
func saveTEALToFile(dataDir, address, teal string) (string, error) {
	// Create files directory under the user directory
	filesDir := filepath.Join(dataDir, "users", "default", "files")
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
			m.selectedKey = 0
			m.scrollOffset = 0
		case "enter":
			// Keep filter, exit filter mode
			m.filterActive = false
			m.selectedKey = 0
			m.scrollOffset = 0
		case "backspace":
			if len(m.filterInput) > 0 {
				m.filterInput = m.filterInput[:len(m.filterInput)-1]
				m.selectedKey = 0
				m.scrollOffset = 0
			}
		default:
			if len(msg.String()) == 1 {
				m.filterInput += msg.String()
				m.selectedKey = 0
				m.scrollOffset = 0
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
			m.selectedKey = 0
			m.scrollOffset = 0
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
			visibleHeight := m.height - 12
			if visibleHeight < 3 {
				visibleHeight = 3
			}
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

	case "i":
		// Import key
		m.importFocus = 0 // Start on key type selection
		m.importKeyType = 0
		m.importMnemonicInput = ""
		m.importError = ""
		m.viewState = ViewImportForm

	case "d":
		// Delete selected key - show confirmation dialog
		if len(displayKeys) > 0 && m.selectedKey < len(displayKeys) {
			m.deleteAddress = displayKeys[m.selectedKey].Address
			m.deleteKeyType = displayKeys[m.selectedKey].KeyType
			m.deleteConfirmFocus = 0 // Default to Cancel (safer)
			m.viewState = ViewDeleteConfirm
		}

	case "e":
		// Export selected key's mnemonic - go to confirmation first
		if len(displayKeys) > 0 && m.selectedKey < len(displayKeys) {
			m.exportConfirmAddress = displayKeys[m.selectedKey].Address
			m.exportConfirmKeyType = displayKeys[m.selectedKey].KeyType
			m.exportConfirmPassphrase = ""
			m.exportConfirmError = ""
			m.viewState = ViewExportConfirm
		}

	case "r":
		// Refresh key list
		return m, refreshKeyList()

	case "enter":
		// Show key details
		if len(displayKeys) > 0 && m.selectedKey < len(displayKeys) {
			return m, tea.Batch(SendGetKeyDetailsCmd(displayKeys[m.selectedKey].Address), WaitForMessageCmd())
		}
	}

	return m, nil
}

// handleKeyDetailsKeys handles keyboard input on key details screen
func (m Model) handleKeyDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", " ", "q":
		m.viewState = ViewKeyList
		m.detailsScrollOffset = 0 // Reset scroll on close
		m.detailsShowTEAL = false
		m.detailsSaveStatus = ""
		return m, nil

	case "t":
		// Toggle between parameters and TEAL view (for any key with TEAL source)
		if m.detailsTEAL != "" {
			m.detailsShowTEAL = !m.detailsShowTEAL
			m.detailsScrollOffset = 0 // Reset scroll when toggling
		}
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

	case "v":
		// View TEAL in pager (only if TEAL is available)
		if m.detailsTEAL != "" && m.dataDir != "" {
			filePath, err := saveTEALToFile(m.dataDir, m.detailsAddress, m.detailsTEAL)
			if err != nil {
				m.detailsSaveStatus = fmt.Sprintf("Save failed: %v", err)
				return m, nil
			}
			// Use less to view the file (suspends TUI, resumes on exit)
			cmd := exec.Command("less", filePath)
			return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
				return ViewerClosedMsg{}
			})
		}
		return m, nil

	case "up", "k":
		// Scroll up
		if m.detailsScrollOffset > 0 {
			m.detailsScrollOffset--
		}
		return m, nil

	case "down", "j":
		// Scroll down - calculate max offset based on content
		maxVisibleLines := 8
		if m.height > 30 {
			maxVisibleLines = 12
		} else if m.height < 20 {
			maxVisibleLines = 5
		}

		var itemCount, visibleItems int
		if m.detailsShowTEAL {
			// TEAL: count lines, show maxVisibleLines
			itemCount = strings.Count(m.detailsTEAL, "\n") + 1
			visibleItems = maxVisibleLines
		} else {
			// Parameters: count params, show half (each takes 2 lines with gap)
			itemCount = len(m.detailsParameters)
			visibleItems = maxVisibleLines / 2
			if visibleItems < 3 {
				visibleItems = 3
			}
		}

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

// refreshKeyList sends a request to refresh the key list
func refreshKeyList() tea.Cmd {
	return SendListKeysCmd()
}
