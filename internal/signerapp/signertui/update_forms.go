// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Form handlers for import, generate, and delete operations.

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

func (m Model) handleBackupConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.backup.exportPassphrase = ""
		m.backup.confirmPassphrase = ""
		m.backup.confirmError = ""
		m.viewState = ViewKeyList
		return m, nil
	case "tab":
		m.backup.confirmFocus = (m.backup.confirmFocus + 1) % 2
		return m, nil
	case "shift+tab":
		m.backup.confirmFocus = (m.backup.confirmFocus + 1) % 2
		return m, nil
	case "enter":
		if m.backup.confirmFocus == 0 {
			m.backup.confirmFocus = 1
			return m, nil
		}
		if m.backup.exportPassphrase == "" {
			m.backup.confirmError = "Please enter an export passphrase"
			return m, nil
		}
		if m.backup.exportPassphrase != m.backup.confirmPassphrase {
			m.backup.confirmError = "Passphrases do not match"
			return m, nil
		}
		passphrase := m.backup.exportPassphrase
		m.backup.exportPassphrase = ""
		m.backup.confirmPassphrase = ""
		m.backup.confirmError = ""
		m.viewState = ViewBackingUp
		return m, tea.Batch(m.sendBackupCmd(passphrase), m.waitForMessageCmd())
	case "backspace":
		if m.backup.confirmFocus == 0 {
			if len(m.backup.exportPassphrase) > 0 {
				m.backup.exportPassphrase = m.backup.exportPassphrase[:len(m.backup.exportPassphrase)-1]
			}
		} else {
			if len(m.backup.confirmPassphrase) > 0 {
				m.backup.confirmPassphrase = m.backup.confirmPassphrase[:len(m.backup.confirmPassphrase)-1]
			}
		}
		m.backup.confirmError = ""
		return m, nil
	default:
		if len(msg.String()) == 1 {
			if m.backup.confirmFocus == 0 {
				m.backup.exportPassphrase += msg.String()
			} else {
				m.backup.confirmPassphrase += msg.String()
			}
			m.backup.confirmError = ""
		}
	}
	return m, nil
}

func (m Model) handleBackupDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "enter", " ":
		m.backup.archivePath = ""
		m.backup.skippedKeys = nil
		m.viewState = ViewKeyList
		return m, nil
	}
	return m, nil
}

// handleGenerateDisplayKeys handles keyboard input on generate display screen
func (m Model) handleGenerateDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "enter", " ":
		m.selectKeyByAddress(m.forms.generatedAddress)
		m.forms.generatedAddress = ""
		m.forms.generatedKeyType = ""
		m.viewState = ViewKeyList
	}

	return m, nil
}

// handleImportDisplayKeys handles keyboard input on import display screen
func (m Model) handleImportDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "enter", " ":
		// Return to key list
		m.forms.importedAddress = ""
		m.forms.importedKeyType = ""
		m.viewState = ViewKeyList
	}

	return m, nil
}

// handleImportFormKeys handles keyboard input on import form
func (m Model) handleImportFormKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.forms.importFocus == 1 {
		switch msg.String() {
		case "esc":
			m.forms.importMnemonicInput.SetValue("")
			m.forms.importMnemonicInput.Blur()
			m.forms.importError = ""
			m.viewState = ViewKeyList
			return m, nil
		case "tab":
			return m.setImportFocus(2)
		case "shift+tab":
			return m.setImportFocus(0)
		case "enter":
			return m.submitImport()
		}

		if msg.Type == tea.KeySpace {
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}}
		}
		var cmd tea.Cmd
		m.forms.importMnemonicInput, cmd = m.forms.importMnemonicInput.Update(msg)
		m.forms.importError = ""
		return m, cmd
	}

	switch msg.String() {
	case "esc":
		// Cancel and return to key list
		m.forms.importMnemonicInput.SetValue("")
		m.forms.importMnemonicInput.Blur()
		m.forms.importError = ""
		m.viewState = ViewKeyList
		return m, nil

	case "tab":
		// Cycle through fields
		return m.setImportFocus((m.forms.importFocus + 1) % 3)

	case "shift+tab":
		// Cycle backwards through fields
		return m.setImportFocus((m.forms.importFocus + 2) % 3)

	case "up":
		// In key type field, switch to previous type
		if m.forms.importFocus == 0 && m.forms.importKeyType > 0 {
			m.forms.importKeyType--
		}
		return m, nil

	case "k":
		// In key type field, vim-style up navigation
		if m.forms.importFocus == 0 {
			if m.forms.importKeyType > 0 {
				m.forms.importKeyType--
			}
		}
		return m, nil

	case "down":
		// In key type field, switch to next type (dynamic bounds)
		if m.forms.importFocus == 0 && m.forms.importKeyType < getImportKeyTypeCount()-1 {
			m.forms.importKeyType++
		}
		return m, nil

	case "j":
		// In key type field, vim-style down navigation (dynamic bounds)
		if m.forms.importFocus == 0 {
			if m.forms.importKeyType < getImportKeyTypeCount()-1 {
				m.forms.importKeyType++
			}
		}
		return m, nil

	case "enter":
		if m.forms.importFocus == 2 {
			return m.submitImport()
		}
		// In key type field, move to next field
		if m.forms.importFocus == 0 {
			return m.setImportFocus(1)
		}
		return m, nil

	case "left", "right", "delete", "home", "end", "insert", "pgup", "pgdown":
		// Ignore navigation/editing keys not supported in these fields
		return m, nil

	case " ":
		// Space - add to mnemonic or submit if on button
		switch m.forms.importFocus {
		case 2:
			return m.submitImport()
		}
		return m, nil

	default:
	}

	return m, nil
}

func (m Model) setImportFocus(focus int) (tea.Model, tea.Cmd) {
	m.forms.importFocus = focus
	if m.forms.importFocus == 1 {
		return m, m.forms.importMnemonicInput.Focus()
	}
	m.forms.importMnemonicInput.Blur()
	return m, nil
}

func (m Model) importMnemonic() string {
	return strings.Join(strings.Fields(m.forms.importMnemonicInput.Value()), " ")
}

func (m Model) submitImport() (tea.Model, tea.Cmd) {
	mnemonic := m.importMnemonic()
	if mnemonic == "" {
		m.forms.importError = "Please enter a mnemonic phrase"
		return m, nil
	}
	if wordCount, expected := len(strings.Fields(mnemonic)), getExpectedImportWordCount(m.forms.importKeyType); wordCount != expected {
		m.forms.importError = fmt.Sprintf("Recovery phrase must contain %d words, got %d", expected, wordCount)
		return m, nil
	}

	keyType := getImportKeyTypeByIndex(m.forms.importKeyType)
	if keyType == "" {
		m.forms.importError = "Invalid key type selected"
		return m, nil
	}

	if spec := getParamSpecForKeyType(keyType); spec != nil {
		m = m.initGenericLSigParamsForKeyType(keyType)
		m.forms.generateFocus = 0
		m.forms.importError = ""
		m.viewState = ViewImportParams
		return m, nil
	}

	return m, tea.Batch(m.sendImportKeyCmd(keyType, mnemonic), m.waitForMessageCmd())
}

// handleImportParamsKeys handles keyboard input on parameter input modal for import.
func (m Model) handleImportParamsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	mnemonic := m.importMnemonic()
	submitFn := func(keyType string, params map[string]string) tea.Cmd {
		return tea.Batch(m.sendImportKeyWithParamsCmd(keyType, mnemonic, params), m.waitForMessageCmd())
	}
	m, cmd, errStr := m.handleParamModalKeys(msg, m.forms.importKeyType, ViewImportForm, ViewImporting, submitFn)
	if errStr != "" || m.viewState == ViewImporting || m.viewState == ViewImportForm {
		m.forms.importError = errStr
	}
	return m, cmd
}

// handleGenerateFormKeys handles keyboard input on key type selection form.
// This is a clean selection screen - parameter input happens in ViewGenerateParams.
func (m Model) handleGenerateFormKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Cancel and return to key list
		m.forms.generateError = ""
		m.viewState = ViewKeyList
		return m, nil

	case "up", "k":
		// Move to previous key type
		if m.forms.generateKeyType > 0 {
			m.forms.generateKeyType--
		}
		return m, nil

	case "down", "j":
		// Move to next key type
		if m.forms.generateKeyType < getKeyTypeCount()-1 {
			m.forms.generateKeyType++
		}
		return m, nil

	case "t", "T":
		keyType := getKeyTypeByIndex(m.forms.generateKeyType)
		tmpl, ok := m.generateTemplateDetailsForKeyType(keyType)
		if !ok {
			m.forms.generateError = fmt.Sprintf("%s has no template details available", displayKeyType(keyType))
			return m, nil
		}
		m.library.detailsReturnView = ViewGenerateForm
		next, cmd, errMsg := m.openLibraryTemplateDetails(tmpl)
		if errMsg != "" {
			next.forms.generateError = errMsg
			return next, nil
		}
		next.forms.generateError = ""
		return next, cmd

	case "enter", " ":
		keyType := getKeyTypeByIndex(m.forms.generateKeyType)
		if keyType == "" {
			m.forms.generateError = "Invalid key type selected"
			return m, nil
		}

		// For parameterized LSigs, transition to parameter input modal
		if spec := getParamSpecForKeyType(keyType); spec != nil {
			m = m.initGenericLSigParams(m.forms.generateKeyType)
			m.forms.generateFocus = 0 // Start at first parameter
			m.forms.generateError = ""
			m.viewState = ViewGenerateParams
			return m, nil
		}

		// For non-parameterized keys, generate immediately
		m.forms.generateError = ""
		m.viewState = ViewGenerating // Show loading state
		return m, tea.Batch(m.sendGenerateKeyCmd(keyType, ""), m.waitForMessageCmd())
	}

	return m, nil
}

func (m Model) generateTemplateDetailsForKeyType(keyType string) (LibraryTemplateInfo, bool) {
	if tmpl, ok := m.findLibraryTemplateForKeyType(keyType); ok {
		return tmpl, true
	}
	info, ok := findServerKeyType(keyType)
	if !ok || !info.RequiresLogicSig {
		return LibraryTemplateInfo{}, false
	}
	return LibraryTemplateInfo{
		KeyType:      info.KeyType,
		TemplateType: libraryTypeCompiledProvider,
		DisplayName:  info.DisplayName,
		Description:  info.Description,
		Parameters:   info.CreationParams,
		RuntimeArgs:  info.RuntimeArgs,
		Installed:    true,
		Enabled:      true,
	}, true
}

func (m Model) findLibraryTemplateForKeyType(keyType string) (LibraryTemplateInfo, bool) {
	for _, tmpl := range m.library.templates {
		if tmpl.KeyType == keyType {
			return tmpl, true
		}
	}
	return LibraryTemplateInfo{}, false
}

// handleGenerateParamsKeys handles keyboard input on parameter input modal for generate.
func (m Model) handleGenerateParamsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	submitFn := func(keyType string, params map[string]string) tea.Cmd {
		return tea.Batch(m.sendGenerateKeyWithParamsCmd(keyType, "", params), m.waitForMessageCmd())
	}
	m, cmd, errStr := m.handleParamModalKeys(msg, m.forms.generateKeyType, ViewGenerateForm, ViewGenerating, submitFn)
	if errStr != "" || m.viewState == ViewGenerating || m.viewState == ViewGenerateForm {
		m.forms.generateError = errStr
	}
	return m, cmd
}

// handleParamModalKeys is the shared handler for parameter input modals (generate and import).
// Returns the updated model, a tea.Cmd, and an error string for the caller to assign.
func (m Model) handleParamModalKeys(
	msg tea.KeyMsg,
	keyTypeIndex int,
	escView, submitView ViewState,
	submitFn func(string, map[string]string) tea.Cmd,
) (Model, tea.Cmd, string) {
	keyType := getKeyTypeByIndex(keyTypeIndex)
	if escView == ViewImportForm {
		keyType = getImportKeyTypeByIndex(keyTypeIndex)
	}
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		m.viewState = escView
		return m, nil, "Parameters not found"
	}

	params := spec.Params
	maxFocus := len(params)
	if m.forms.genericLSigPasteParam != "" {
		return m.handlePasteOnlyParamInput(msg, params)
	}

	switch msg.String() {
	case "esc":
		m.viewState = escView
		return m, nil, ""

	case "tab":
		m.forms.generateFocus = (m.forms.generateFocus + 1) % (maxFocus + 1)
		if m.forms.generateFocus < len(params) {
			m = m.ensureParamVisible(m.forms.generateFocus, m.getMaxVisibleParams())
		}
		return m, nil, ""

	case "up":
		if m.forms.generateFocus < len(params) && isMultilineParamType(params[m.forms.generateFocus].Type) {
			m = m.scrollCurrentParamInput(params, -1)
			return m, nil, ""
		}
		if m.forms.generateFocus > 0 {
			m.forms.generateFocus--
			if m.forms.generateFocus < len(params) {
				m = m.ensureParamVisible(m.forms.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil, ""

	case "shift+tab", "k":
		if m.forms.generateFocus > 0 {
			m.forms.generateFocus--
			if m.forms.generateFocus < len(params) {
				m = m.ensureParamVisible(m.forms.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil, ""

	case "down":
		if m.forms.generateFocus < len(params) && isMultilineParamType(params[m.forms.generateFocus].Type) {
			m = m.scrollCurrentParamInput(params, 1)
			return m, nil, ""
		}
		if m.forms.generateFocus < maxFocus {
			m.forms.generateFocus++
			if m.forms.generateFocus < len(params) {
				m = m.ensureParamVisible(m.forms.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil, ""

	case "j":
		if m.forms.generateFocus < maxFocus {
			m.forms.generateFocus++
			if m.forms.generateFocus < len(params) {
				m = m.ensureParamVisible(m.forms.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil, ""

	case "<", ">":
		if m.forms.generateFocus < len(params) {
			paramDef := params[m.forms.generateFocus]
			if len(paramDef.Options) > 0 {
				delta := 1
				if msg.String() == "<" {
					delta = -1
				}
				m = m.cycleCurrentParamOption(params, delta)
			} else if len(paramDef.InputModes) > 1 {
				currentMode := m.forms.genericLSigParamModes[paramDef.Name]
				if msg.String() == ">" {
					currentMode = (currentMode + 1) % len(paramDef.InputModes)
				} else {
					currentMode = (currentMode - 1 + len(paramDef.InputModes)) % len(paramDef.InputModes)
				}
				m.forms.genericLSigParamModes[paramDef.Name] = currentMode
				m.forms.genericLSigParams[paramDef.Name] = ""
				m.setParamScroll(paramDef.Name, 0)
			}
		}
		return m, nil, ""

	case "backspace":
		if m.forms.generateFocus < len(params) {
			if isPasteOnlyParam(params[m.forms.generateFocus]) {
				return m, nil, ""
			}
			paramName := params[m.forms.generateFocus].Name
			if m.forms.genericLSigParams != nil {
				if val, ok := m.forms.genericLSigParams[paramName]; ok && len(val) > 0 {
					m.forms.genericLSigParams[paramName] = val[:len(val)-1]
				}
			}
			m = m.ensureCurrentParamInputVisible(params)
		}
		return m, nil, ""

	case "enter", " ":
		if m.forms.generateFocus < len(params) && isPasteOnlyParam(params[m.forms.generateFocus]) {
			m.forms.genericLSigPasteParam = params[m.forms.generateFocus].Name
			return m, nil, ""
		}
		if m.forms.generateFocus < len(params) && isMultilineParamType(params[m.forms.generateFocus].Type) {
			if msg.String() == "enter" {
				m = m.appendToCurrentParam("\n", params)
			} else {
				m = m.appendToCurrentParam(" ", params)
			}
			return m, nil, ""
		}
		if m.forms.generateFocus == maxFocus || msg.String() == "enter" {
			transformedParams, err := m.applyInputModeTransforms(params)
			if err != nil {
				return m, nil, err.Error()
			}
			if err := spec.Validate(transformedParams); err != nil {
				return m, nil, err.Error()
			}
			m.viewState = submitView
			return m, submitFn(keyType, transformedParams), ""
		}
		if m.forms.generateFocus < maxFocus {
			m.forms.generateFocus++
			if m.forms.generateFocus < len(params) {
				m = m.ensureParamVisible(m.forms.generateFocus, m.getMaxVisibleParams())
			}
		}
		return m, nil, ""

	case "pgup", "pgdown":
		if m.forms.generateFocus < len(params) && isMultilineParamType(params[m.forms.generateFocus].Type) {
			paramDef := params[m.forms.generateFocus]
			delta := -getFieldHeightForType(paramDef.Type)
			if msg.String() == "pgdown" {
				delta = getFieldHeightForType(paramDef.Type)
			}
			m = m.scrollCurrentParamInput(params, delta)
		}
		return m, nil, ""

	case "home":
		if m.forms.generateFocus < len(params) {
			m.setParamScroll(params[m.forms.generateFocus].Name, 0)
		}
		return m, nil, ""

	case "end":
		if m.forms.generateFocus < len(params) {
			m = m.ensureCurrentParamInputVisible(params)
		}
		return m, nil, ""

	case "left", "right":
		if m.forms.generateFocus < len(params) && len(params[m.forms.generateFocus].Options) > 0 {
			delta := -1
			if msg.String() == "right" {
				delta = 1
			}
			m = m.cycleCurrentParamOption(params, delta)
		}
		return m, nil, ""

	case "delete":
		if m.forms.generateFocus < len(params) && isPasteOnlyParam(params[m.forms.generateFocus]) {
			m.forms.genericLSigParams[params[m.forms.generateFocus].Name] = ""
		}
		return m, nil, ""

	case "insert":
		return m, nil, ""

	default:
		input := msg.String()
		if len(input) > 0 && m.forms.generateFocus < len(params) && !isPasteOnlyParam(params[m.forms.generateFocus]) {
			m = m.appendToCurrentParam(input, params)
		}
	}

	return m, nil, ""
}

func (m Model) handlePasteOnlyParamInput(msg tea.KeyMsg, params []lsigprovider.ParameterDef) (Model, tea.Cmd, string) {
	paramIdx := m.forms.generateFocus
	if paramIdx < 0 || paramIdx >= len(params) || params[paramIdx].Name != m.forms.genericLSigPasteParam {
		m.forms.genericLSigPasteParam = ""
		return m, nil, ""
	}
	if msg.String() == "esc" {
		m.forms.genericLSigPasteParam = ""
		return m, nil, ""
	}
	if !msg.Paste {
		return m, nil, ""
	}

	value, err := normalizePastedParam(string(msg.Runes), params[paramIdx])
	if err != nil {
		return m, nil, err.Error()
	}
	m.forms.genericLSigParams[params[paramIdx].Name] = value
	m.forms.genericLSigPasteParam = ""
	return m, nil, ""
}

func normalizePastedParam(input string, paramDef lsigprovider.ParameterDef) (string, error) {
	var value strings.Builder
	for _, r := range strings.TrimSpace(input) {
		if paramDef.Type == "bytes" {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				continue
			}
			if r >= 'A' && r <= 'F' {
				r += 'a' - 'A'
			}
			if !((r >= 'a' && r <= 'f') || (r >= '0' && r <= '9')) {
				return "", fmt.Errorf("pasted %s contains non-hexadecimal characters", paramDef.Label)
			}
		} else if r < 32 || r > 126 {
			return "", fmt.Errorf("pasted %s contains unsupported characters", paramDef.Label)
		}
		value.WriteRune(r)
	}
	if value.Len() == 0 {
		return "", fmt.Errorf("pasted %s is empty", paramDef.Label)
	}
	maxLen := getMaxInputLengthForType(paramDef.Type, paramDef.MaxLength)
	if value.Len() > maxLen {
		return "", fmt.Errorf("pasted %s exceeds the maximum length of %d characters", paramDef.Label, maxLen)
	}
	return value.String(), nil
}

// initGenericLSigParams initializes the parameter map for a generic LogicSig.
// keyTypeIndex is the index into the key type list (use m.forms.generateKeyType or m.forms.importKeyType).
func (m Model) initGenericLSigParams(keyTypeIndex int) Model {
	keyType := getKeyTypeByIndex(keyTypeIndex)
	return m.initGenericLSigParamsForKeyType(keyType)
}

func (m Model) initGenericLSigParamsForKeyType(keyType string) Model {
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		return m
	}

	params := spec.Params
	m.forms.genericLSigParams = make(map[string]string)
	m.forms.genericLSigParamOrder = make([]string, len(params))
	m.forms.genericLSigParamModes = make(map[string]int)
	m.forms.genericLSigParamScroll = make(map[string]int)
	m.forms.genericLSigPasteParam = ""
	for i, p := range params {
		m.forms.genericLSigParamOrder[i] = p.Name
		m.forms.genericLSigParams[p.Name] = defaultParamValue(p)
		m.forms.genericLSigParamModes[p.Name] = 0 // Default to first input mode
		m.forms.genericLSigParamScroll[p.Name] = 0
	}
	m.forms.generateParamScrollOffset = 0 // Reset scroll when initializing params
	return m
}

// ensureParamVisible adjusts scroll offset to ensure the focused parameter is visible.
func (m Model) ensureParamVisible(paramIdx, maxVisibleParams int) Model {
	if paramIdx < 0 {
		return m
	}
	// Scroll up if focused param is above visible area
	if paramIdx < m.forms.generateParamScrollOffset {
		m.forms.generateParamScrollOffset = paramIdx
	}
	// Scroll down if focused param is below visible area
	if paramIdx >= m.forms.generateParamScrollOffset+maxVisibleParams {
		m.forms.generateParamScrollOffset = paramIdx - maxVisibleParams + 1
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
	maxVisibleParams := availableHeight / 8
	if maxVisibleParams < 1 {
		maxVisibleParams = 1
	}
	return maxVisibleParams
}

// appendToCurrentParam appends input to the currently focused parameter field.
// It strips bracketed paste sequences and other non-printable characters.
// Note: In ViewGenerateParams, focus 0..N-1 are parameters (not 1..N like before).
func (m Model) appendToCurrentParam(input string, params []lsigprovider.ParameterDef) Model {
	if m.forms.genericLSigParams == nil {
		// Safety fallback: determine key type index based on view state
		keyTypeIndex := m.forms.generateKeyType
		keyType := getKeyTypeByIndex(keyTypeIndex)
		if m.viewState == ViewImportParams {
			keyTypeIndex = m.forms.importKeyType
			keyType = getImportKeyTypeByIndex(keyTypeIndex)
		}
		m = m.initGenericLSigParamsForKeyType(keyType)
	}

	paramIdx := m.forms.generateFocus // Focus is now 0-indexed for params
	if paramIdx < 0 || paramIdx >= len(params) {
		return m
	}

	paramDef := params[paramIdx]
	if len(paramDef.Options) > 0 {
		return m
	}
	currentVal := m.forms.genericLSigParams[paramDef.Name]

	// Determine effective input type (mode's InputType overrides paramDef.Type)
	effectiveType := paramDef.Type
	if len(paramDef.InputModes) > 1 && m.forms.genericLSigParamModes != nil {
		modeIdx := m.forms.genericLSigParamModes[paramDef.Name]
		if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) {
			mode := paramDef.InputModes[modeIdx]
			if mode.InputType != "" {
				effectiveType = mode.InputType
			}
		}
	}

	maxLen := getMaxInputLengthForType(effectiveType, paramDef.MaxLength)
	lineMaxLen := 0
	if effectiveType == "address[]" {
		lineMaxLen = getFieldWidthForType(effectiveType, paramDef.MaxLength) - 1
		if lineMaxLen < 1 {
			lineMaxLen = 1
		}
	}

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
		case "address[]":
			if char == '\r' {
				continue
			}
			if char == ',' || char == ' ' {
				char = '\n'
			}
			if char == '\n' || char == '@' {
				allowed = true
				break
			}
			if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
				allowed = true
			}
		case "uint64":
			// Numbers only
			if char >= '0' && char <= '9' {
				allowed = true
			}
		case "bytes":
			// Hex characters only (0-9, a-f, A-F)
			if char >= 'A' && char <= 'F' {
				char = char - 'A' + 'a'
			}
			if (char >= 'a' && char <= 'f') || (char >= '0' && char <= '9') {
				allowed = true
			}
		default:
			// Accept printable ASCII characters only (strips escape sequences, brackets from paste, etc.)
			if char >= 32 && char <= 126 {
				allowed = true
			}
		}

		if allowed && len(currentVal) < maxLen {
			if lineMaxLen > 0 && char != '\n' && currentParamLineLength(currentVal) >= lineMaxLen {
				continue
			}
			currentVal += string(char)
		}
	}

	m.forms.genericLSigParams[paramDef.Name] = currentVal
	m = m.ensureCurrentParamInputVisible(params)
	return m
}

func defaultParamValue(paramDef lsigprovider.ParameterDef) string {
	if paramDef.Default != "" {
		return paramDef.Default
	}
	if len(paramDef.Options) > 0 {
		return paramDef.Options[0]
	}
	return ""
}

func (m Model) cycleCurrentParamOption(params []lsigprovider.ParameterDef, delta int) Model {
	if m.forms.generateFocus < 0 || m.forms.generateFocus >= len(params) {
		return m
	}
	paramDef := params[m.forms.generateFocus]
	if len(paramDef.Options) == 0 {
		return m
	}
	current := indexOfOption(paramDef.Options, m.forms.genericLSigParams[paramDef.Name])
	if current < 0 {
		current = 0
	} else {
		current = (current + delta + len(paramDef.Options)) % len(paramDef.Options)
	}
	m.forms.genericLSigParams[paramDef.Name] = paramDef.Options[current]
	return m
}

func indexOfOption(options []string, value string) int {
	for i, option := range options {
		if option == value {
			return i
		}
	}
	return -1
}

func (m Model) ensureCurrentParamInputVisible(params []lsigprovider.ParameterDef) Model {
	paramIdx := m.forms.generateFocus
	if paramIdx < 0 || paramIdx >= len(params) {
		return m
	}
	paramDef := params[paramIdx]
	value := ""
	if m.forms.genericLSigParams != nil {
		value = m.forms.genericLSigParams[paramDef.Name]
	}
	if !isMultilineParamType(paramDef.Type) {
		return m
	}
	lines := paramInputLines(value)
	maxOffset := maxParamInputScrollOffset(lines, getFieldHeightForType(paramDef.Type))
	m.setParamScroll(paramDef.Name, maxOffset)
	return m
}

func (m Model) scrollCurrentParamInput(params []lsigprovider.ParameterDef, delta int) Model {
	paramIdx := m.forms.generateFocus
	if paramIdx < 0 || paramIdx >= len(params) {
		return m
	}
	paramDef := params[paramIdx]
	current := 0
	if m.forms.genericLSigParamScroll != nil {
		current = m.forms.genericLSigParamScroll[paramDef.Name]
	}
	value := ""
	if m.forms.genericLSigParams != nil {
		value = m.forms.genericLSigParams[paramDef.Name]
	}
	if !isMultilineParamType(paramDef.Type) {
		return m
	}
	lines := paramInputLines(value)
	maxOffset := maxParamInputScrollOffset(lines, getFieldHeightForType(paramDef.Type))
	next := current + delta
	if next < 0 {
		next = 0
	}
	if next > maxOffset {
		next = maxOffset
	}
	m.setParamScroll(paramDef.Name, next)
	return m
}

func (m *Model) setParamScroll(paramName string, offset int) {
	if m.forms.genericLSigParamScroll == nil {
		m.forms.genericLSigParamScroll = make(map[string]int)
	}
	m.forms.genericLSigParamScroll[paramName] = offset
}

func paramInputLines(value string) []string {
	lines := strings.Split(value, "\n")
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func maxParamInputScrollOffset(lines []string, fieldHeight int) int {
	if fieldHeight < 1 {
		fieldHeight = 1
	}
	maxOffset := len(lines) - fieldHeight
	if maxOffset < 0 {
		return 0
	}
	return maxOffset
}

func currentParamLineLength(value string) int {
	lastNewline := strings.LastIndex(value, "\n")
	if lastNewline >= 0 {
		value = value[lastNewline+1:]
	}
	return len([]rune(value))
}

// handleDeleteConfirmKeys handles keyboard input on delete confirmation dialog
func (m Model) handleDeleteConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		// Cancel and return to key list
		m.del.address = ""
		m.del.keyType = ""
		m.viewState = ViewKeyList
		return m, nil

	case "tab", "left", "right", "h", "l":
		// Toggle between Cancel and Delete buttons
		m.del.focus = (m.del.focus + 1) % 2
		return m, nil

	case "enter", " ":
		if m.del.focus == 0 {
			// Cancel selected
			m.del.address = ""
			m.del.keyType = ""
			m.viewState = ViewKeyList
			return m, nil
		}
		// Delete selected - send delete request
		m.viewState = ViewDeleting // Show loading state
		return m, tea.Batch(m.sendDeleteKeyCmd(m.del.address), m.waitForMessageCmd())

	case "y":
		// Quick confirm delete
		m.viewState = ViewDeleting // Show loading state
		return m, tea.Batch(m.sendDeleteKeyCmd(m.del.address), m.waitForMessageCmd())
	}

	return m, nil
}

// handleRevokeTokenConfirmKeys handles keyboard input on token revocation confirmation dialog
func (m Model) handleRevokeTokenConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		m.viewState = ViewAdminPanel
		return m, nil

	case "tab", "left", "right", "h", "l":
		m.admin.revokeTokenFocus = (m.admin.revokeTokenFocus + 1) % 2
		return m, nil

	case "enter", " ":
		if m.admin.revokeTokenFocus == 0 {
			// Cancel
			m.viewState = ViewAdminPanel
			return m, nil
		}
		// Revoke - send IPC request
		m.viewState = ViewAdminPanel
		return m, tea.Batch(m.sendRevokeTokenCmd(), m.waitForMessageCmd())

	case "y":
		// Quick confirm
		m.viewState = ViewAdminPanel
		return m, tea.Batch(m.sendRevokeTokenCmd(), m.waitForMessageCmd())
	}

	return m, nil
}

func (m Model) openManualLockConfirm() (tea.Model, tea.Cmd) {
	m.manualLock.focus = 0
	m.manualLock.returnView = m.viewState
	m.viewState = ViewLockConfirm
	return m, nil
}

// handleLockConfirmKeys handles keyboard input on the manual lock confirmation dialog.
func (m Model) handleLockConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		m.manualLock.focus = 0
		m.viewState = m.lockConfirmReturnView()
		return m, nil

	case "tab", "left", "right", "h", "l":
		m.manualLock.focus = (m.manualLock.focus + 1) % 2
		return m, nil

	case "enter", " ":
		if m.manualLock.focus == 0 {
			m.viewState = m.lockConfirmReturnView()
			return m, nil
		}
		return m.startManualLock()

	case "y":
		return m.startManualLock()
	}

	return m, nil
}

func (m Model) startManualLock() (tea.Model, tea.Cmd) {
	m.manualLock.pending = true
	m.manualLock.focus = 0
	m.viewState = m.lockConfirmReturnView()
	m.lastError = ""
	return m, tea.Batch(m.sendLockIdentityCmd(manualLockReason), m.waitForMessageCmd())
}

// handleDisplaceConfirmKeys handles keyboard input on the displacement confirmation modal
func (m Model) handleDisplaceConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		// Cancel - disconnect and exit
		m.disconnectAdminClient()
		return m, tea.Quit

	case "y":
		// Quick confirm - displace the existing client
		return m, tea.Batch(m.sendDisplaceConfirmCmd(), m.waitForMessageCmd())

	case "tab", "left", "right", "h", "l":
		// Toggle between Cancel and Proceed buttons
		m.displaceConfirmFocus = (m.displaceConfirmFocus + 1) % 2
		return m, nil

	case "enter", " ":
		if m.displaceConfirmFocus == 1 {
			// Proceed - displace the existing client
			return m, tea.Batch(m.sendDisplaceConfirmCmd(), m.waitForMessageCmd())
		}
		// Cancel - disconnect and exit
		m.disconnectAdminClient()
		return m, tea.Quit
	}

	return m, nil
}

// applyInputModeTransforms applies any transforms required by selected input modes.
// For example, if a user selected "preimage" mode for a hash parameter, this hashes the input.
func (m Model) applyInputModeTransforms(params []lsigprovider.ParameterDef) (map[string]string, error) {
	result := make(map[string]string)

	for _, paramDef := range params {
		value := m.forms.genericLSigParams[paramDef.Name]
		if value == "" && len(paramDef.Options) > 0 {
			value = defaultParamValue(paramDef)
		}
		if paramDef.Type == "address[]" {
			var err error
			value, err = resolveAddressListValue(m.dataDir, value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", paramDef.Name, err)
			}
		}

		// Check if this parameter has input modes and the selected mode requires a transform.
		if len(paramDef.InputModes) > 0 {
			modeIdx := m.forms.genericLSigParamModes[paramDef.Name]
			if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) {
				mode := paramDef.InputModes[modeIdx]

				// Apply transform based on mode
				switch mode.Transform {
				case "sha256", "sha512_256":
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

					switch mode.Transform {
					case "sha256":
						hash := sha256.Sum256(inputBytes)
						value = hex.EncodeToString(hash[:])
					case "sha512_256":
						hash := sha512.Sum512_256(inputBytes)
						value = hex.EncodeToString(hash[:])
					}
				}
			}
		}

		result[paramDef.Name] = value
	}

	return lsigprovider.NormalizeCreationParams(result, params)
}

// selectKeyByAddress sets the selected key index to the key matching the given address.
// It also adjusts scrollOffset to ensure the key is visible.
func (m *Model) selectKeyByAddress(address string) {
	for _, k := range m.keylist.keys {
		if k.Address == address {
			m.keylist.tab = m.effectiveKeyListTab()
			m.keylist.selectedKey = 0
			for i, displayKey := range m.filteredKeys() {
				if displayKey.Address == address {
					m.keylist.selectedKey = i
					break
				}
			}
			visibleHeight := m.keyListVisibleHeight()
			if m.keylist.selectedKey < m.keylist.scrollOffset {
				m.keylist.scrollOffset = m.keylist.selectedKey
			} else if m.keylist.selectedKey >= m.keylist.scrollOffset+visibleHeight {
				m.keylist.scrollOffset = m.keylist.selectedKey - visibleHeight + 1
			}
			return
		}
	}
}
