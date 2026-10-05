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
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
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
		id := m.beginOperation(ViewBackingUp)
		return m, tea.Batch(m.sendBackupCmd(passphrase, id), m.waitForMessageCmd())
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
		m.viewState = ViewKeyList
		return m, nil
	}
	return m, nil
}

// handleGenerateDisplayKeys handles keyboard input on generate display screen
func (m Model) handleGenerateDisplayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "e":
		return m.openGeneratedCosignerExport()
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
	submitFn := func(keyType string, params map[string]string, id string) tea.Cmd {
		return tea.Batch(m.sendImportKeyWithParamsCmd(keyType, mnemonic, params, id), m.waitForMessageCmd())
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
		id := m.beginOperation(ViewGenerating)
		return m, tea.Batch(m.sendGenerateKeyCmd(keyType, "", id), m.waitForMessageCmd())
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
	if msg.String() == "esc" && m.cosigner.generateFromManager {
		m.cosigner.generateFromManager = false
		m.forms.generateError = ""
		m.viewState = ViewCosignerReferenceDetails
		return m, nil
	}
	submitFn := func(keyType string, params map[string]string, id string) tea.Cmd {
		return tea.Batch(m.sendGenerateKeyWithParamsCmd(keyType, "", params, id), m.waitForMessageCmd())
	}
	m, cmd, errStr := m.handleParamModalKeys(msg, m.forms.generateKeyType, ViewGenerateForm, ViewGenerating, submitFn)
	if errStr != "" || m.viewState == ViewGenerating || m.viewState == ViewGenerateForm {
		m.forms.generateError = errStr
	}
	return m, cmd
}

// handleParamModalKeys is the shared handler for parameter input modals (generate and import).
// Returns the updated model, a tea.Cmd, and an error string for the caller to assign.
// Focus 0..len(params)-1 are the fields; len(params) is the submit button.
func (m Model) handleParamModalKeys(
	msg tea.KeyMsg,
	keyTypeIndex int,
	escView, submitView ViewState,
	submitFn func(keyType string, params map[string]string, id string) tea.Cmd,
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

	if param, ok := focusedParam(m.forms.generateFocus, params); ok && m.isCosignerSelectorParam(keyType, param) {
		if next, handled, errText := m.handleCosignerSelectorKey(msg, keyType, param); handled {
			return next, nil, errText
		}
	}
	if input, ok := paramTextInput(msg, m.forms.generateFocus, params); ok {
		return m.typeIntoCurrentParam(input, params)
	}

	focused, onField := focusedParam(m.forms.generateFocus, params)
	multiline := onField && isMultilineParamType(focused.Type)
	switch key := msg.String(); key {
	case "esc":
		m.viewState = escView
	case "tab":
		m = m.wrapParamFocusForward(params)
	case "up", "down":
		delta := 1
		if key == "up" {
			delta = -1
		}
		if multiline {
			m = m.scrollCurrentParamInput(params, delta)
		} else {
			m = m.moveParamFocus(delta, params)
		}
	case "shift+tab", "k":
		m = m.moveParamFocus(-1, params)
	case "j":
		m = m.moveParamFocus(1, params)
	case "<", ">":
		if onField {
			m = m.cycleParamChoiceOrMode(focused, params, key == ">")
		}
	case "left", "right":
		if onField && len(focused.Options) > 0 {
			m = m.cycleCurrentParamOption(params, choiceDelta(key == "right"))
		}
	case "backspace":
		if onField {
			m = m.deleteLastParamChar(focused.Name, params)
		}
	case "enter", " ":
		switch {
		case multiline:
			m = m.appendToCurrentParam("\n", params)
		case m.forms.generateFocus == len(params) || key == "enter":
			return m.submitParamModal(keyType, spec, submitView, submitFn)
		default:
			m = m.moveParamFocus(1, params)
		}
	case "pgup", "pgdown":
		if multiline {
			page := getFieldHeightForType(focused.Type)
			if key == "pgup" {
				page = -page
			}
			m = m.scrollCurrentParamInput(params, page)
		}
	case "home":
		if onField {
			m.setParamScroll(focused.Name, 0)
		}
	case "end":
		if onField {
			m = m.ensureCurrentParamInputVisible(params)
		}
	case "insert", "delete":
	default:
		input := key
		if msg.Type == tea.KeyRunes {
			input = string(msg.Runes)
		}
		if input != "" && onField {
			return m.typeIntoCurrentParam(input, params)
		}
	}
	return m, nil, ""
}

// focusedParam returns the field at focus, or false when focus is on the
// submit button or out of range.
func focusedParam(focus int, params []lsigprovider.ParameterDef) (lsigprovider.ParameterDef, bool) {
	if focus < 0 || focus >= len(params) {
		return lsigprovider.ParameterDef{}, false
	}
	return params[focus], true
}

func choiceDelta(forward bool) int {
	if forward {
		return 1
	}
	return -1
}

// handleCosignerSelectorKey handles a key on a cosigner selector field, which
// is chosen from a picker rather than typed. It reports false for keys the
// generic handler should process (navigation).
func (m Model) handleCosignerSelectorKey(msg tea.KeyMsg, keyType string, param lsigprovider.ParameterDef) (Model, bool, string) {
	switch msg.String() {
	case "enter", " ":
		next, errText := m.openCosignerPicker(keyType, param.Name)
		return next, true, errText
	case "left", "right", "<", ">", "backspace", "delete", "insert":
		return m, true, ""
	}
	if msg.Type == tea.KeyRunes {
		return m, true, ""
	}
	return m, false, ""
}

// typeIntoCurrentParam appends typed text to the focused field.
func (m Model) typeIntoCurrentParam(input string, params []lsigprovider.ParameterDef) (Model, tea.Cmd, string) {
	if !isASCIIText(input) {
		return m, nil, errParamNonASCII
	}
	return m.appendToCurrentParam(input, params), nil, ""
}

// moveParamFocus moves focus one step toward the fields' end (delta > 0) or
// start (delta < 0), stopping at the submit button and the first field, and
// keeps a newly focused field scrolled into view.
func (m Model) moveParamFocus(delta int, params []lsigprovider.ParameterDef) Model {
	switch {
	case delta < 0 && m.forms.generateFocus > 0:
		m.forms.generateFocus--
	case delta > 0 && m.forms.generateFocus < len(params):
		m.forms.generateFocus++
	default:
		return m
	}
	if m.forms.generateFocus < len(params) {
		m = m.ensureParamVisible(m.forms.generateFocus, m.getMaxVisibleParams())
	}
	return m
}

// wrapParamFocusForward moves focus forward, wrapping from the submit button
// to the first field.
func (m Model) wrapParamFocusForward(params []lsigprovider.ParameterDef) Model {
	m.forms.generateFocus = (m.forms.generateFocus + 1) % (len(params) + 1)
	if m.forms.generateFocus < len(params) {
		m = m.ensureParamVisible(m.forms.generateFocus, m.getMaxVisibleParams())
	}
	return m
}

// cycleParamChoiceOrMode steps a choice field to its next or previous option,
// or a field with several input modes to its next or previous mode, clearing
// the value typed in the old mode.
func (m Model) cycleParamChoiceOrMode(param lsigprovider.ParameterDef, params []lsigprovider.ParameterDef, forward bool) Model {
	if len(param.Options) > 0 {
		return m.cycleCurrentParamOption(params, choiceDelta(forward))
	}
	if modes := len(param.InputModes); modes > 1 {
		mode := (m.forms.genericLSigParamModes[param.Name] + choiceDelta(forward) + modes) % modes
		m.forms.genericLSigParamModes[param.Name] = mode
		m.forms.genericLSigParams[param.Name] = ""
		m.setParamScroll(param.Name, 0)
	}
	return m
}

func (m Model) deleteLastParamChar(name string, params []lsigprovider.ParameterDef) Model {
	if val := m.forms.genericLSigParams[name]; val != "" {
		m.forms.genericLSigParams[name] = val[:len(val)-1]
	}
	return m.ensureCurrentParamInputVisible(params)
}

// submitParamModal validates the form and starts the submit operation.
func (m Model) submitParamModal(
	keyType string,
	spec *paramSpec,
	submitView ViewState,
	submitFn func(keyType string, params map[string]string, id string) tea.Cmd,
) (Model, tea.Cmd, string) {
	for _, param := range spec.Params {
		if m.isCosignerSelectorParam(keyType, param) && strings.TrimSpace(m.forms.genericLSigParams[param.Name]) == "" {
			return m, nil, "Choose a cosigner before continuing"
		}
	}
	transformedParams, err := m.applyInputModeTransforms(spec.Params)
	if err != nil {
		return m, nil, err.Error()
	}
	if err := spec.Validate(transformedParams); err != nil {
		return m, nil, err.Error()
	}
	id := m.beginOperation(submitView)
	return m, submitFn(keyType, transformedParams, id), ""
}

const errParamNonASCII = "Parameters accept ASCII characters only"

// paramTextInput returns the text a key types into the focused parameter when
// that key would otherwise navigate. j, k, space, < and > move focus or cycle
// choices elsewhere, but type into a free-text field. Choice fields and the
// submit button keep the navigation meaning.
func paramTextInput(msg tea.KeyMsg, focus int, params []lsigprovider.ParameterDef) (string, bool) {
	if focus < 0 || focus >= len(params) || len(params[focus].Options) > 0 || msg.Paste {
		return "", false
	}
	switch key := msg.String(); key {
	case "j", "k", " ":
		return key, true
	case "<", ">":
		return key, len(params[focus].InputModes) <= 1
	}
	return "", false
}

func isASCIIText(input string) bool {
	for _, r := range input {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
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

	effectiveType := m.effectiveParamInputType(paramDef)
	maxLen := getMaxInputLengthForType(effectiveType, paramDef.MaxLength)
	if isContractAdminReferenceParam(paramDef) {
		maxLen = 4096
	}
	lineMaxLen := 0
	if effectiveType == "address[]" {
		lineMaxLen = max(getFieldWidthForType(effectiveType, paramDef.MaxLength)-1, 1)
	}

	for _, r := range input {
		char, allowed := paramInputChar(effectiveType, r)
		if !allowed || len(currentVal) >= maxLen {
			continue
		}
		if lineMaxLen > 0 && char != '\n' && currentParamLineLength(currentVal) >= lineMaxLen {
			continue
		}
		currentVal += string(char)
	}

	m.forms.genericLSigParams[paramDef.Name] = currentVal
	m = m.ensureCurrentParamInputVisible(params)
	return m
}

// effectiveParamInputType is the type that governs what may be typed into a
// field: the selected input mode's type overrides the declared type, and a
// contract-admin reference is a free-text file path.
func (m Model) effectiveParamInputType(paramDef lsigprovider.ParameterDef) string {
	if isContractAdminReferenceParam(paramDef) {
		return "string"
	}
	if len(paramDef.InputModes) > 1 && m.forms.genericLSigParamModes != nil {
		modeIdx := m.forms.genericLSigParamModes[paramDef.Name]
		if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) && paramDef.InputModes[modeIdx].InputType != "" {
			return paramDef.InputModes[modeIdx].InputType
		}
	}
	return paramDef.Type
}

// paramInputChar normalizes one typed rune for a field of the given type and
// reports whether the field accepts it. Non-ASCII runes are never accepted,
// so a wider rune is never narrowed to the ASCII byte it happens to end in.
func paramInputChar(inputType string, r rune) (byte, bool) {
	if r > unicode.MaxASCII {
		return 0, false
	}
	char := byte(r)
	isDigit := char >= '0' && char <= '9'
	switch inputType {
	case "address":
		// Algorand addresses are base32: uppercase alphanumeric.
		if char >= 'a' && char <= 'z' {
			char = char - 'a' + 'A'
		}
		return char, (char >= 'A' && char <= 'Z') || isDigit
	case "address[]":
		switch char {
		case '\r':
			return 0, false
		case ',', ' ':
			char = '\n'
		}
		isLetter := (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z')
		return char, char == '\n' || char == '@' || isLetter || isDigit
	case "uint64":
		return char, isDigit
	case "bytes":
		// Hex, normalized to lowercase.
		if char >= 'A' && char <= 'F' {
			char = char - 'A' + 'a'
		}
		return char, (char >= 'a' && char <= 'f') || isDigit
	default:
		// Printable ASCII only: strips escape sequences and paste brackets.
		return char, char >= 32 && char <= 126
	}
}

func defaultParamValue(paramDef lsigprovider.ParameterDef) string {
	if paramDef.Name == cosignerrefs.ParamCosignerName && len(paramDef.Options) > 1 {
		return ""
	}
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
		id := m.beginOperation(ViewDeleting)
		return m, tea.Batch(m.sendDeleteKeyCmd(m.del.address, id), m.waitForMessageCmd())

	case "y":
		// Quick confirm delete
		id := m.beginOperation(ViewDeleting)
		return m, tea.Batch(m.sendDeleteKeyCmd(m.del.address, id), m.waitForMessageCmd())
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
		if isContractAdminReferenceParam(paramDef) {
			var err error
			value, err = loadContractAdminPublicKey(value)
			if err != nil {
				return nil, err
			}
		}
		if value == "" && len(paramDef.Options) > 0 {
			value = defaultParamValue(paramDef)
		}
		if paramDef.Type == "address[]" {
			var err error
			value, err = resolveAddressListValue(value)
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
