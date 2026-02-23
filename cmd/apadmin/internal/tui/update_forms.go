// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

// Form handlers for import, generate, export, and delete operations.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

// handleExportConfirmKeys handles keyboard input on export confirmation screen
func (m Model) handleExportConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Cancel and return to key list
		m.exportConfirmAddress = ""
		m.exportConfirmKeyType = ""
		m.exportConfirmPassphrase = ""
		m.exportConfirmError = ""
		m.viewState = ViewKeyList
		return m, nil

	case "enter":
		// Send passphrase verification request along with export
		if m.exportConfirmPassphrase == "" {
			m.exportConfirmError = "Please enter your passphrase"
			return m, nil
		}
		address := m.exportConfirmAddress
		passphrase := m.exportConfirmPassphrase
		m.exportConfirmPassphrase = "" // Clear immediately for security
		m.exportConfirmError = ""
		return m, tea.Batch(SendExportKeyWithPassphraseCmd(address, passphrase), WaitForMessageCmd())

	case "backspace":
		if len(m.exportConfirmPassphrase) > 0 {
			m.exportConfirmPassphrase = m.exportConfirmPassphrase[:len(m.exportConfirmPassphrase)-1]
			m.exportConfirmError = "" // Clear error on edit
		}
		return m, nil

	default:
		// Add character to passphrase input
		if len(msg.String()) == 1 {
			m.exportConfirmPassphrase += msg.String()
			m.exportConfirmError = "" // Clear error on edit
		}
	}

	return m, nil
}

// handleExportDisplayKeys handles keyboard input on export display screen
func (m Model) handleExportDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "enter", " ":
		// Return to key list with exported key selected
		m.selectKeyByAddress(m.exportedAddress)
		m.exportedMnemonic = ""
		m.exportedAddress = ""
		m.exportedKeyType = ""
		m.exportedWordCount = 0
		m.exportedParameters = nil
		m.viewState = ViewKeyList
		return m, nil
	}

	return m, nil
}

// handleGenerateDisplayKeys handles keyboard input on generate display screen
func (m Model) handleGenerateDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "e":
		// Show the mnemonic directly (address already verified on this screen)
		m.generatedAddress = ""
		m.generatedKeyType = ""
		m.viewState = ViewExportDisplay
		return m, nil

	case "q", "esc", "enter", " ":
		// Return to key list with newly generated key selected
		m.selectKeyByAddress(m.generatedAddress)
		m.generatedAddress = ""
		m.generatedKeyType = ""
		m.exportedMnemonic = ""
		m.exportedAddress = ""
		m.exportedKeyType = ""
		m.exportedWordCount = 0
		m.exportedParameters = nil
		m.viewState = ViewKeyList
	}

	return m, nil
}

// handleImportDisplayKeys handles keyboard input on import display screen
func (m Model) handleImportDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "enter", " ":
		// Return to key list
		m.importedAddress = ""
		m.importedKeyType = ""
		m.viewState = ViewKeyList
	}

	return m, nil
}

// handleImportFormKeys handles keyboard input on import form
func (m Model) handleImportFormKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Cancel and return to key list
		m.importMnemonicInput = ""
		m.importError = ""
		m.viewState = ViewKeyList
		return m, nil

	case "tab":
		// Cycle through fields
		m.importFocus = (m.importFocus + 1) % 3
		return m, nil

	case "shift+tab":
		// Cycle backwards through fields
		m.importFocus = (m.importFocus + 2) % 3
		return m, nil

	case "up":
		// In key type field, switch to previous type
		if m.importFocus == 0 && m.importKeyType > 0 {
			m.importKeyType--
		}
		return m, nil

	case "k":
		// In key type field, vim-style up navigation
		if m.importFocus == 0 {
			if m.importKeyType > 0 {
				m.importKeyType--
			}
			return m, nil
		}
		// In mnemonic field, add as character
		if m.importFocus == 1 {
			m.importMnemonicInput += "k"
		}
		return m, nil

	case "down":
		// In key type field, switch to next type (dynamic bounds)
		if m.importFocus == 0 && m.importKeyType < getKeyTypeCount()-1 {
			m.importKeyType++
		}
		return m, nil

	case "j":
		// In key type field, vim-style down navigation (dynamic bounds)
		if m.importFocus == 0 {
			if m.importKeyType < getKeyTypeCount()-1 {
				m.importKeyType++
			}
			return m, nil
		}
		// In mnemonic field, add as character
		if m.importFocus == 1 {
			m.importMnemonicInput += "j"
		}
		return m, nil

	case "enter":
		if m.importFocus == 2 || m.importFocus == 1 {
			// Submit the import (dynamic key type lookup)
			keyType := getKeyTypeByIndex(m.importKeyType)
			if keyType == "" {
				m.importError = "Invalid key type selected"
				return m, nil
			}
			if m.importMnemonicInput == "" {
				m.importError = "Please enter a mnemonic phrase"
				return m, nil
			}
			if spec := getParamSpecForKeyType(keyType); spec != nil {
				m = m.initGenericLSigParams(m.importKeyType)
				m.generateFocus = 0
				m.importError = ""
				m.viewState = ViewImportParams
				return m, nil
			}
			return m, tea.Batch(SendImportKeyCmd(keyType, m.importMnemonicInput), WaitForMessageCmd())
		}
		// In key type field, move to next field
		if m.importFocus == 0 {
			m.importFocus = 1
		}
		return m, nil

	case "backspace":
		// Delete character from mnemonic input
		if m.importFocus == 1 && len(m.importMnemonicInput) > 0 {
			m.importMnemonicInput = m.importMnemonicInput[:len(m.importMnemonicInput)-1]
		}
		return m, nil

	case "left", "right", "delete", "home", "end", "insert", "pgup", "pgdown":
		// Ignore navigation/editing keys not supported in these fields
		return m, nil

	case " ":
		// Space - add to mnemonic or submit if on button
		switch m.importFocus {
		case 1:
			m.importMnemonicInput += " "
		case 2:
			// Submit (dynamic key type lookup)
			keyType := getKeyTypeByIndex(m.importKeyType)
			if keyType == "" {
				m.importError = "Invalid key type selected"
				return m, nil
			}
			if m.importMnemonicInput == "" {
				m.importError = "Please enter a mnemonic phrase"
				return m, nil
			}
			if spec := getParamSpecForKeyType(keyType); spec != nil {
				m = m.initGenericLSigParams(m.importKeyType)
				m.generateFocus = 0
				m.importError = ""
				m.viewState = ViewImportParams
				return m, nil
			}
			return m, tea.Batch(SendImportKeyCmd(keyType, m.importMnemonicInput), WaitForMessageCmd())
		}
		return m, nil

	default:
		// Add character(s) to mnemonic input if in that field
		// This handles both single keystrokes and pasted text
		if m.importFocus == 1 {
			input := msg.String()
			// Filter to only allow printable characters (letters, numbers, spaces)
			for _, r := range input {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' {
					m.importMnemonicInput += string(r)
				}
			}
		}
	}

	return m, nil
}

// handleImportParamsKeys handles keyboard input on parameter input modal for import.
// Focus states: 0..N-1 = parameters, N = import button
func (m Model) handleImportParamsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	keyType := getKeyTypeByIndex(m.importKeyType)
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		m.importError = "Parameters not found"
		m.viewState = ViewImportForm
		return m, nil
	}

	params := spec.Params
	maxFocus := len(params)

	switch msg.String() {
	case "esc":
		m.importError = ""
		m.viewState = ViewImportForm
		return m, nil

	case "tab":
		m.generateFocus = (m.generateFocus + 1) % (maxFocus + 1)
		if m.generateFocus < len(params) {
			m = m.ensureParamVisible(m.generateFocus, m.getMaxVisibleParams())
		}
		return m, nil

	case "shift+tab", "up", "k":
		if m.generateFocus > 0 {
			m.generateFocus--
			if m.generateFocus < len(params) {
				m = m.ensureParamVisible(m.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil

	case "down", "j":
		if m.generateFocus < maxFocus {
			m.generateFocus++
			if m.generateFocus < len(params) {
				m = m.ensureParamVisible(m.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil

	case "<", ">":
		if m.generateFocus < len(params) {
			paramDef := params[m.generateFocus]
			if len(paramDef.InputModes) > 1 {
				currentMode := m.genericLSigParamModes[paramDef.Name]
				if msg.String() == ">" {
					currentMode = (currentMode + 1) % len(paramDef.InputModes)
				} else {
					currentMode = (currentMode - 1 + len(paramDef.InputModes)) % len(paramDef.InputModes)
				}
				m.genericLSigParamModes[paramDef.Name] = currentMode
				m.genericLSigParams[paramDef.Name] = ""
			}
		}
		return m, nil

	case "backspace":
		if m.generateFocus < len(params) {
			paramName := params[m.generateFocus].Name
			if m.genericLSigParams != nil {
				if val, ok := m.genericLSigParams[paramName]; ok && len(val) > 0 {
					m.genericLSigParams[paramName] = val[:len(val)-1]
				}
			}
		}
		return m, nil

	case "enter", " ":
		if m.generateFocus == maxFocus || msg.String() == "enter" {
			transformedParams, err := m.applyInputModeTransforms(params)
			if err != nil {
				m.importError = err.Error()
				return m, nil
			}

			if err := spec.Validate(transformedParams); err != nil {
				m.importError = err.Error()
				return m, nil
			}

			m.importError = ""
			m.viewState = ViewImporting
			return m, tea.Batch(SendImportKeyWithParamsCmd(keyType, m.importMnemonicInput, transformedParams), WaitForMessageCmd())
		}
		if m.generateFocus < maxFocus {
			m.generateFocus++
			if m.generateFocus < len(params) {
				m = m.ensureParamVisible(m.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil

	case "left", "right", "delete", "home", "end", "insert", "pgup", "pgdown":
		return m, nil

	default:
		input := msg.String()
		if len(input) > 0 && m.generateFocus < len(params) {
			m = m.appendToCurrentParam(input, params)
		}
	}

	return m, nil
}

// handleGenerateFormKeys handles keyboard input on key type selection form.
// This is a clean selection screen - parameter input happens in ViewGenerateParams.
func (m Model) handleGenerateFormKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Cancel and return to key list
		m.generateError = ""
		m.viewState = ViewKeyList
		return m, nil

	case "up", "k":
		// Move to previous key type
		if m.generateKeyType > 0 {
			m.generateKeyType--
		}
		return m, nil

	case "down", "j":
		// Move to next key type
		if m.generateKeyType < getKeyTypeCount()-1 {
			m.generateKeyType++
		}
		return m, nil

	case "enter", " ":
		keyType := getKeyTypeByIndex(m.generateKeyType)
		if keyType == "" {
			m.generateError = "Invalid key type selected"
			return m, nil
		}

		// For parameterized LSigs, transition to parameter input modal
		if spec := getParamSpecForKeyType(keyType); spec != nil {
			m = m.initGenericLSigParams(m.generateKeyType)
			m.generateFocus = 0 // Start at first parameter
			m.generateError = ""
			m.viewState = ViewGenerateParams
			return m, nil
		}

		// For non-parameterized keys, generate immediately
		m.generateError = ""
		m.viewState = ViewGenerating // Show loading state
		return m, tea.Batch(SendGenerateKeyCmd(keyType, ""), WaitForMessageCmd())
	}

	return m, nil
}

// handleGenerateParamsKeys handles keyboard input on parameter input modal.
// Focus states: 0..N-1 = parameters, N = generate button
func (m Model) handleGenerateParamsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	keyType := getKeyTypeByIndex(m.generateKeyType)
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		m.generateError = "Parameters not found"
		m.viewState = ViewGenerateForm
		return m, nil
	}

	params := spec.Params
	maxFocus := len(params) // 0..N-1 = params, N = generate button

	switch msg.String() {
	case "esc":
		// Return to key type selection (keep params for potential re-entry)
		m.generateError = ""
		m.viewState = ViewGenerateForm
		return m, nil

	case "tab":
		// Cycle through fields
		m.generateFocus = (m.generateFocus + 1) % (maxFocus + 1)
		// Auto-scroll to keep focused param visible
		if m.generateFocus < len(params) {
			m = m.ensureParamVisible(m.generateFocus, m.getMaxVisibleParams())
		}
		return m, nil

	case "shift+tab", "up", "k":
		// Move to previous field (no wrap)
		if m.generateFocus > 0 {
			m.generateFocus--
			if m.generateFocus < len(params) {
				m = m.ensureParamVisible(m.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil

	case "down", "j":
		// Move to next field (no wrap)
		if m.generateFocus < maxFocus {
			m.generateFocus++
			if m.generateFocus < len(params) {
				m = m.ensureParamVisible(m.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil

	case "<", ">":
		// Toggle input mode for parameters with multiple modes
		if m.generateFocus < len(params) {
			paramDef := params[m.generateFocus]
			if len(paramDef.InputModes) > 1 {
				currentMode := m.genericLSigParamModes[paramDef.Name]
				if msg.String() == ">" {
					currentMode = (currentMode + 1) % len(paramDef.InputModes)
				} else {
					currentMode = (currentMode - 1 + len(paramDef.InputModes)) % len(paramDef.InputModes)
				}
				m.genericLSigParamModes[paramDef.Name] = currentMode
				// Clear input when switching modes (different format expected)
				m.genericLSigParams[paramDef.Name] = ""
			}
		}
		return m, nil

	case "backspace":
		// Handle backspace in parameter fields
		if m.generateFocus < len(params) {
			paramName := params[m.generateFocus].Name
			if m.genericLSigParams != nil {
				if val, ok := m.genericLSigParams[paramName]; ok && len(val) > 0 {
					m.genericLSigParams[paramName] = val[:len(val)-1]
				}
			}
		}
		return m, nil

	case "enter", " ":
		// On generate button or any field with Enter, attempt to generate
		if m.generateFocus == maxFocus || msg.String() == "enter" {
			// Apply input mode transforms before validation
			transformedParams, err := m.applyInputModeTransforms(params)
			if err != nil {
				m.generateError = err.Error()
				return m, nil
			}

			// Validate parameters using provider/template
			if err := spec.Validate(transformedParams); err != nil {
				m.generateError = err.Error()
				return m, nil
			}

			m.generateError = ""
			m.viewState = ViewGenerating // Show loading state
			return m, tea.Batch(SendGenerateKeyWithParamsCmd(keyType, "", transformedParams), WaitForMessageCmd())
		}
		// Space on a parameter field moves to next field
		if m.generateFocus < maxFocus {
			m.generateFocus++
			if m.generateFocus < len(params) {
				m = m.ensureParamVisible(m.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil

	case "left", "right", "delete", "home", "end", "insert", "pgup", "pgdown":
		// Ignore navigation/editing keys not supported in these fields
		return m, nil

	default:
		// Handle text input for parameter fields (supports paste)
		// appendToCurrentParam filters out escape sequences and validates characters
		input := msg.String()
		if len(input) > 0 && m.generateFocus < len(params) {
			m = m.appendToCurrentParam(input, params)
		}
	}

	return m, nil
}

// initGenericLSigParams initializes the parameter map for a generic LogicSig.
// keyTypeIndex is the index into the key type list (use m.generateKeyType or m.importKeyType).
func (m Model) initGenericLSigParams(keyTypeIndex int) Model {
	keyType := getKeyTypeByIndex(keyTypeIndex)
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		return m
	}

	params := spec.Params
	m.genericLSigParams = make(map[string]string)
	m.genericLSigParamOrder = make([]string, len(params))
	m.genericLSigParamModes = make(map[string]int)
	for i, p := range params {
		m.genericLSigParamOrder[i] = p.Name
		m.genericLSigParams[p.Name] = ""
		m.genericLSigParamModes[p.Name] = 0 // Default to first input mode
	}
	m.generateParamScrollOffset = 0 // Reset scroll when initializing params
	return m
}

// ensureParamVisible adjusts scroll offset to ensure the focused parameter is visible.
func (m Model) ensureParamVisible(paramIdx, maxVisibleParams int) Model {
	if paramIdx < 0 {
		return m
	}
	// Scroll up if focused param is above visible area
	if paramIdx < m.generateParamScrollOffset {
		m.generateParamScrollOffset = paramIdx
	}
	// Scroll down if focused param is below visible area
	if paramIdx >= m.generateParamScrollOffset+maxVisibleParams {
		m.generateParamScrollOffset = paramIdx - maxVisibleParams + 1
	}
	return m
}

// getMaxVisibleParams returns max visible params based on terminal height.
func (m Model) getMaxVisibleParams() int {
	reservedLines := 18
	availableHeight := m.height - reservedLines
	if availableHeight < 8 {
		availableHeight = 8
	}
	maxVisibleParams := availableHeight / 4
	if maxVisibleParams < 2 {
		maxVisibleParams = 2
	}
	return maxVisibleParams
}

// appendToCurrentParam appends input to the currently focused parameter field.
// It strips bracketed paste sequences and other non-printable characters.
// Note: In ViewGenerateParams, focus 0..N-1 are parameters (not 1..N like before).
func (m Model) appendToCurrentParam(input string, params []lsigprovider.ParameterDef) Model {
	if m.genericLSigParams == nil {
		// Safety fallback: determine key type index based on view state
		keyTypeIndex := m.generateKeyType
		if m.viewState == ViewImportParams {
			keyTypeIndex = m.importKeyType
		}
		m = m.initGenericLSigParams(keyTypeIndex)
	}

	paramIdx := m.generateFocus // Focus is now 0-indexed for params
	if paramIdx < 0 || paramIdx >= len(params) {
		return m
	}

	paramDef := params[paramIdx]
	currentVal := m.genericLSigParams[paramDef.Name]

	// Determine effective input type (mode's InputType overrides paramDef.Type)
	effectiveType := paramDef.Type
	if len(paramDef.InputModes) > 1 && m.genericLSigParamModes != nil {
		modeIdx := m.genericLSigParamModes[paramDef.Name]
		if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) {
			mode := paramDef.InputModes[modeIdx]
			if mode.InputType != "" {
				effectiveType = mode.InputType
			}
		}
	}

	maxLen := getMaxInputLengthForType(effectiveType, paramDef.MaxLength)

	for _, r := range input {
		char := byte(r)
		allowed := false

		switch effectiveType {
		case "address":
			// Algorand addresses are base32 - uppercase alphanumeric
			if char >= 'a' && char <= 'z' {
				char = char - 'a' + 'A'
			}
			if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
				allowed = true
			}
		case "uint64":
			// Numbers only
			if char >= '0' && char <= '9' {
				allowed = true
			}
		case "bytes":
			// Hex characters only (0-9, a-f, A-F)
			if char >= 'a' && char <= 'f' {
				char = char - 'a' + 'A' // Uppercase for consistency
			}
			if (char >= 'A' && char <= 'F') || (char >= '0' && char <= '9') {
				allowed = true
			}
		default:
			// Accept printable ASCII characters only (strips escape sequences, brackets from paste, etc.)
			if char >= 32 && char <= 126 {
				allowed = true
			}
		}

		if allowed && len(currentVal) < maxLen {
			currentVal += string(char)
		}
	}

	m.genericLSigParams[paramDef.Name] = currentVal
	return m
}

// handleDeleteConfirmKeys handles keyboard input on delete confirmation dialog
func (m Model) handleDeleteConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		// Cancel and return to key list
		m.deleteAddress = ""
		m.deleteKeyType = ""
		m.viewState = ViewKeyList
		return m, nil

	case "tab", "left", "right", "h", "l":
		// Toggle between Cancel and Delete buttons
		m.deleteConfirmFocus = (m.deleteConfirmFocus + 1) % 2
		return m, nil

	case "enter", " ":
		if m.deleteConfirmFocus == 0 {
			// Cancel selected
			m.deleteAddress = ""
			m.deleteKeyType = ""
			m.viewState = ViewKeyList
			return m, nil
		}
		// Delete selected - send delete request
		m.viewState = ViewDeleting // Show loading state
		return m, tea.Batch(SendDeleteKeyCmd(m.deleteAddress), WaitForMessageCmd())

	case "y":
		// Quick confirm delete
		m.viewState = ViewDeleting // Show loading state
		return m, tea.Batch(SendDeleteKeyCmd(m.deleteAddress), WaitForMessageCmd())
	}

	return m, nil
}

// handleDisplaceConfirmKeys handles keyboard input on the displacement confirmation modal
func (m Model) handleDisplaceConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		// Cancel - disconnect gracefully without displacing
		if globalIPCClient != nil {
			globalIPCClient.Disconnect()
		}
		m.connectionState = ConnectionDisconnected
		m.viewState = ViewAuth
		return m, nil

	case "y":
		// Quick confirm - displace the existing client
		return m, tea.Batch(SendDisplaceConfirmCmd(), WaitForMessageCmd())

	case "tab", "left", "right", "h", "l":
		// Toggle between Cancel and Proceed buttons
		m.displaceConfirmFocus = (m.displaceConfirmFocus + 1) % 2
		return m, nil

	case "enter", " ":
		if m.displaceConfirmFocus == 1 {
			// Proceed - displace the existing client
			return m, tea.Batch(SendDisplaceConfirmCmd(), WaitForMessageCmd())
		}
		// Cancel
		if globalIPCClient != nil {
			globalIPCClient.Disconnect()
		}
		m.connectionState = ConnectionDisconnected
		m.viewState = ViewAuth
		return m, nil
	}

	return m, nil
}

// applyInputModeTransforms applies any transforms required by selected input modes.
// For example, if a user selected "preimage" mode for a hash parameter, this hashes the input.
func (m Model) applyInputModeTransforms(params []lsigprovider.ParameterDef) (map[string]string, error) {
	result := make(map[string]string)

	for _, paramDef := range params {
		value := m.genericLSigParams[paramDef.Name]

		// Check if this parameter has input modes and a non-default mode is selected
		if len(paramDef.InputModes) > 1 {
			modeIdx := m.genericLSigParamModes[paramDef.Name]
			if modeIdx > 0 && modeIdx < len(paramDef.InputModes) {
				mode := paramDef.InputModes[modeIdx]

				// Apply transform based on mode
				switch mode.Transform {
				case "sha256":
					if value == "" {
						result[paramDef.Name] = ""
						continue
					}

					var inputBytes []byte
					if mode.InputType == "string" {
						// String input: use raw bytes directly
						inputBytes = []byte(value)
					} else {
						// Hex input: decode first
						var err error
						inputBytes, err = hex.DecodeString(value)
						if err != nil {
							return nil, fmt.Errorf("%s: invalid hex input for %s mode", paramDef.Name, mode.Name)
						}
					}

					hash := sha256.Sum256(inputBytes)
					value = hex.EncodeToString(hash[:])
				}
			}
		}

		result[paramDef.Name] = value
	}

	return result, nil
}

// selectKeyByAddress sets the selected key index to the key matching the given address.
// It also adjusts scrollOffset to ensure the key is visible.
func (m *Model) selectKeyByAddress(address string) {
	for i, k := range m.keys {
		if k.Address == address {
			m.selectedKey = i
			// Ensure visible: use same visibleHeight formula as key list rendering
			visibleHeight := m.height - 12
			if visibleHeight < 3 {
				visibleHeight = 3
			}
			if m.selectedKey < m.scrollOffset {
				m.scrollOffset = m.selectedKey
			} else if m.selectedKey >= m.scrollOffset+visibleHeight {
				m.scrollOffset = m.selectedKey - visibleHeight + 1
			}
			return
		}
	}
}
