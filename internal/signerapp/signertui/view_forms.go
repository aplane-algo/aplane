// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Form view rendering for import, generate, and delete operations.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

func (m Model) renderBackupConfirm() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Create Backup"))
	sb.WriteString("\n")
	if dir := m.backupDirectoryLabel(); dir != "" {
		sb.WriteString(subtitleStyle.Render("Backup Directory: " + dir))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString("\n")
	}
	sb.WriteString(subtitleStyle.Render(fmt.Sprintf(
		"Scope: back up all active credentials of this identity (%d %s).",
		m.keyCount,
		pluralKeys(m.keyCount),
	)))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("A signer-managed backup archive will be written to the identity backup store."))
	sb.WriteString("\n\n")

	exportStyle := inputInactiveStyle
	confirmStyle := inputInactiveStyle
	if m.backup.confirmFocus == 0 {
		exportStyle = inputActiveStyle
	}
	if m.backup.confirmFocus == 1 {
		confirmStyle = inputActiveStyle
	}
	if m.backup.confirmError != "" {
		if m.backup.confirmFocus == 0 {
			exportStyle = exportStyle.BorderForeground(lipgloss.Color("196"))
		} else {
			confirmStyle = confirmStyle.BorderForeground(lipgloss.Color("196"))
		}
	}

	sb.WriteString("Export passphrase:\n")
	exportMasked := strings.Repeat("*", len(m.backup.exportPassphrase))
	if exportMasked == "" {
		exportMasked = " "
	}
	sb.WriteString(exportStyle.Width(40).Render(exportMasked))
	sb.WriteString("\n\n")

	sb.WriteString("Confirm export passphrase:\n")
	confirmMasked := strings.Repeat("*", len(m.backup.confirmPassphrase))
	if confirmMasked == "" {
		confirmMasked = " "
	}
	sb.WriteString(confirmStyle.Width(40).Render(confirmMasked))
	sb.WriteString("\n")

	if m.backup.confirmError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(m.backup.confirmError))
		sb.WriteString("\n")
	}

	return m.renderPopup(80, sb.String())
}

func (m Model) renderBackingUp() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Creating Backup"))
	sb.WriteString("\n\n")
	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")
	return m.renderPopup(70, sb.String())
}

func (m Model) renderBackupDisplay() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Backup Created"))
	sb.WriteString("\n\n")
	sb.WriteString("Archive path:\n")
	sb.WriteString(m.backup.archivePath)
	sb.WriteString("\n")
	return m.renderPopup(90, sb.String())
}

// renderImportForm renders the key import form
func (m Model) renderImportForm() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Import Key from Mnemonic"))
	sb.WriteString("\n\n")

	// Key type selection (dynamically built from registered algorithms)
	keyTypes := getKeyTypeOptions()
	sb.WriteString("Key Type:\n")
	for i, kt := range keyTypes {
		prefix := "  "
		if i == m.forms.importKeyType {
			prefix = "> "
		}
		if m.forms.importFocus == 0 && i == m.forms.importKeyType {
			sb.WriteString(selectedStyle.Render(prefix + kt))
		} else if i == m.forms.importKeyType {
			sb.WriteString(keyTypeStyle.Render(prefix + kt))
		} else {
			sb.WriteString(subtitleStyle.Render(prefix + kt))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// Mnemonic input
	sb.WriteString("Mnemonic Phrase:\n")
	mnemonicInput := m.forms.importMnemonicInput
	mnemonicInput.SetWidth(62)
	mnemonicInput.SetHeight(4)
	mnemonicInput.MaxHeight = 4
	if m.forms.importFocus == 1 {
		_ = mnemonicInput.Focus()
		sb.WriteString(inputStyle.Width(64).Render(mnemonicInput.View()))
	} else {
		mnemonicInput.Blur()
		sb.WriteString(subtitleStyle.Render(mnemonicInput.View()))
	}
	sb.WriteString("\n\n")

	// Word count indicator (dynamically determined by selected key type)
	wordCount := 0
	if value := m.forms.importMnemonicInput.Value(); value != "" {
		wordCount = len(strings.Fields(value))
	}
	expectedWords := getExpectedImportWordCount(m.forms.importKeyType)
	wordCountStr := fmt.Sprintf("Words: %d/%d", wordCount, expectedWords)
	if wordCount == expectedWords {
		sb.WriteString(statusUnlockedStyle.Render(wordCountStr))
	} else {
		sb.WriteString(subtitleStyle.Render(wordCountStr))
	}
	sb.WriteString("\n\n")
	if notice := keyTypeGenerationNotice(getImportKeyTypeByIndex(m.forms.importKeyType)); notice != "" {
		sb.WriteString(subtitleStyle.Render(notice))
		sb.WriteString("\n\n")
	}

	// Submit button
	var importBtn string
	if m.forms.importFocus == 2 {
		importBtn = buttonActiveStyle.Render("IMPORT KEY")
	} else {
		importBtn = buttonInactiveStyle.Render("IMPORT KEY")
	}
	sb.WriteString(importBtn)
	sb.WriteString("\n\n")

	// Error message
	if m.forms.importError != "" {
		sb.WriteString(errorStyle.Render(m.forms.importError))
		sb.WriteString("\n")
	}

	return m.renderPopup(70, sb.String())
}

// renderImportDisplay renders the key import confirmation screen
func (m Model) renderImportDisplay() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Key Imported Successfully"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("%s: %s\n", m.keyIdentifierLabel(m.forms.importedKeyType), m.forms.importedAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", displayKeyType(m.forms.importedKeyType)))
	sb.WriteString("\n")

	return m.renderPopup(75, sb.String())
}

// renderGenerateForm renders the key type selection form
func (m Model) renderGenerateForm() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Generate New Key"))
	sb.WriteString("\n\n")

	// Key type selection (dynamically built from registered algorithms)
	keyTypes := getGenerateKeyTypeOptions()
	sb.WriteString("Select Key Type:\n\n")
	for i, kt := range keyTypes {
		prefix := "  "
		if i == m.forms.generateKeyType {
			prefix = "> "
		}
		if i == m.forms.generateKeyType {
			sb.WriteString(selectedStyle.Render(prefix + kt))
		} else {
			sb.WriteString(subtitleStyle.Render(prefix + kt))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// Selected key type label.
	selectedKeyType := getKeyTypeByIndex(m.forms.generateKeyType)
	sb.WriteString(subtitleStyle.Render(getKeyTypeSelectionLabel(selectedKeyType)))
	sb.WriteString("\n\n")
	if notice := keyTypeGenerationNotice(selectedKeyType); notice != "" {
		sb.WriteString(subtitleStyle.Render(notice))
		sb.WriteString("\n\n")
	}

	// Error message
	if m.forms.generateError != "" {
		sb.WriteString(errorStyle.Render(m.forms.generateError))
		sb.WriteString("\n")
	}

	return m.renderPopup(70, sb.String())
}

// renderParameterModal renders the shared parameter input modal for both generate and import.
// buttonVerb is "GENERATE" or "IMPORT".
func (m Model) renderParameterModal(keyTypeIndex int, buttonVerb, errorMsg string) string {
	selectedKeyType := getKeyTypeByIndex(keyTypeIndex)
	return m.renderParameterModalForKeyType(selectedKeyType, buttonVerb, errorMsg)
}

func (m Model) renderParameterModalForKeyType(keyType, buttonVerb, errorMsg string) string {
	var sb strings.Builder

	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		return m.renderPopup(70, "Error: parameters not available")
	}

	sb.WriteString(titleStyle.Render(fmt.Sprintf("%s Parameters", spec.DisplayName)))
	sb.WriteString("\n\n")

	params := spec.Params
	sb.WriteString(scrollMoreAboveLine(m.forms.generateParamScrollOffset))
	sb.WriteString("\n")

	// Render only the fields that fit the terminal.
	startIdx := m.forms.generateParamScrollOffset
	endIdx := min(startIdx+m.visibleParamModalFields(), len(params))
	for i := startIdx; i < endIdx; i++ {
		m.renderParamField(&sb, keyType, params[i], m.forms.generateFocus == i)
	}

	sb.WriteString(scrollMoreBelowLine(len(params) - endIdx))
	sb.WriteString("\n")

	// Action button
	if m.forms.generateFocus == len(params) {
		sb.WriteString(buttonActiveStyle.Render(fmt.Sprintf("> [ %s %s ] <", buttonVerb, strings.ToUpper(spec.DisplayName))))
	} else {
		sb.WriteString(buttonInactiveStyle.Render(fmt.Sprintf("  [ %s %s ]  ", buttonVerb, strings.ToUpper(spec.DisplayName))))
	}
	sb.WriteString("\n\n")

	if errorMsg != "" {
		sb.WriteString(errorStyle.Render(errorMsg))
		sb.WriteString("\n\n")
	}

	return m.renderPopup(80, sb.String())
}

// visibleParamModalFields is how many parameter fields the modal renders at
// the current terminal height.
func (m Model) visibleParamModalFields() int {
	const reservedLines = 12 // title + button + help + error + margins
	availableHeight := max(m.height-reservedLines, 12)
	return max(availableHeight/8, 1)
}

// renderParamField writes one parameter field: its label line, the input box,
// and, for a scrolled multi-line field, how many lines are hidden.
func (m Model) renderParamField(sb *strings.Builder, keyType string, paramDef lsigprovider.ParameterDef, focused bool) {
	isCosignerSelector := m.isCosignerSelectorParam(keyType, paramDef)
	isAdminReference := isContractAdminReferenceParam(paramDef)

	labelText, modeHint := m.paramFieldLabel(paramDef, focused, isCosignerSelector, isAdminReference)
	if focused {
		sb.WriteString("> " + labelText + ":")
	} else {
		sb.WriteString("  " + labelText + ":")
	}
	if modeHint != "" {
		sb.WriteString(subtitleStyle.Render(modeHint))
	}
	sb.WriteString("\n")

	fieldWidth := m.constrainParameterFieldWidth(m.paramFieldWidth(paramDef, isCosignerSelector, isAdminReference))
	fieldHeight := m.constrainParameterFieldHeight(getFieldHeightForType(paramDef.Type), sb.String())

	lines := m.paramFieldLines(paramDef, focused, fieldWidth, isCosignerSelector, isAdminReference)
	aboveCount, belowCount := 0, 0
	if isMultilineParamType(paramDef.Type) {
		lines, aboveCount, belowCount = m.scrollParamFieldLines(paramDef.Name, lines, fieldHeight)
	}
	for len(lines) < fieldHeight {
		lines = append(lines, "")
	}
	lines = lines[:fieldHeight]
	for i, line := range lines {
		lines[i] = fixedWidthFieldLine(line, fieldWidth)
	}
	displayValue := strings.Join(lines, "\n")

	if focused {
		sb.WriteString(inputActiveStyle.Render(displayValue))
	} else {
		sb.WriteString(inputInactiveStyle.Render(displayValue))
	}
	sb.WriteString("\n\n")
	if isMultilineParamType(paramDef.Type) && (aboveCount > 0 || belowCount > 0) {
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("  %d above, %d below", aboveCount, belowCount)))
		sb.WriteString("\n")
	}
}

// paramFieldLabel returns a field's label, with its required marker, and the
// key hint shown while it is focused.
func (m Model) paramFieldLabel(paramDef lsigprovider.ParameterDef, focused, isCosignerSelector, isAdminReference bool) (string, string) {
	labelText := paramDef.Label
	if isAdminReference {
		labelText = "Contract Admin Reference File (.wit.json)"
	}
	var modeHint string
	if len(paramDef.InputModes) > 1 {
		modeIdx := 0
		if m.forms.genericLSigParamModes != nil {
			modeIdx = m.forms.genericLSigParamModes[paramDef.Name]
		}
		if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) {
			labelText = paramDef.InputModes[modeIdx].Label
		}
		if focused {
			modeHint = fmt.Sprintf("  [</> to switch: %d/%d]", modeIdx+1, len(paramDef.InputModes))
		}
	}
	if isCosignerSelector && focused {
		modeHint = "  [Enter to choose]"
	} else if len(paramDef.Options) > 0 && focused {
		optionIdx := max(indexOfOption(paramDef.Options, m.forms.genericLSigParams[paramDef.Name]), 0)
		modeHint = fmt.Sprintf("  [</> to choose: %d/%d]", optionIdx+1, len(paramDef.Options))
	}
	return parameterRequirementLabel(labelText, paramDef.Required), modeHint
}

// paramFieldWidth is the unconstrained input box width: the type's width,
// widened or narrowed for special fields, or the selected input mode's hex
// length.
func (m Model) paramFieldWidth(paramDef lsigprovider.ParameterDef, isCosignerSelector, isAdminReference bool) int {
	fieldWidth := getFieldWidthForType(paramDef.Type, paramDef.MaxLength)
	if isAdminReference {
		fieldWidth = 62
	}
	if len(paramDef.Options) > 0 {
		fieldWidth = optionFieldWidth(paramDef.Options)
	}
	if isCosignerSelector {
		fieldWidth = 50
	}
	if len(paramDef.InputModes) > 1 && m.forms.genericLSigParamModes != nil {
		modeIdx := m.forms.genericLSigParamModes[paramDef.Name]
		if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) && paramDef.InputModes[modeIdx].ByteLength > 0 {
			fieldWidth = paramDef.InputModes[modeIdx].ByteLength * 2 // hex encoding
		}
	}
	return fieldWidth
}

// paramFieldLines is the field's content as lines: its value or placeholder,
// or, while focused, its value with a cursor.
func (m Model) paramFieldLines(paramDef lsigprovider.ParameterDef, focused bool, fieldWidth int, isCosignerSelector, isAdminReference bool) []string {
	if focused && m.forms.genericLSigParams != nil {
		currentValue := m.forms.genericLSigParams[paramDef.Name]
		if currentValue == "" && len(paramDef.Options) > 0 {
			currentValue = defaultParamValue(paramDef)
		}
		if isCosignerSelector {
			currentValue = m.cosignerSelectionDisplay(currentValue)
		}
		if isAdminReference {
			if currentRunes := []rune(currentValue); len(currentRunes) >= fieldWidth {
				currentValue = string(currentRunes[len(currentRunes)-fieldWidth+1:])
			}
		}
		lines := paramInputLines(currentValue)
		lines[len(lines)-1] += "_"
		return lines
	}

	value := ""
	if m.forms.genericLSigParams != nil {
		value = m.forms.genericLSigParams[paramDef.Name]
	}
	if value == "" && len(paramDef.Options) > 0 {
		value = defaultParamValue(paramDef)
	}
	if value == "" {
		if isAdminReference {
			value = "Path to public .wit.json on this machine"
		} else {
			value = getPlaceholderForType(paramDef.Type)
		}
	}
	if isCosignerSelector {
		value = m.cosignerSelectionDisplay(m.forms.genericLSigParams[paramDef.Name])
	}
	if isAdminReference && !focused {
		value = middleEllipsize(value, fieldWidth)
	}
	return paramInputLines(value)
}

// scrollParamFieldLines returns the window of a multi-line field's lines at
// its scroll offset, and how many lines are hidden above and below.
func (m Model) scrollParamFieldLines(name string, lines []string, fieldHeight int) ([]string, int, int) {
	offset := 0
	if m.forms.genericLSigParamScroll != nil {
		offset = m.forms.genericLSigParamScroll[name]
	}
	offset = min(max(offset, 0), maxParamInputScrollOffset(lines, fieldHeight))
	end := min(offset+fieldHeight, len(lines))
	return append([]string(nil), lines[offset:end]...), offset, len(lines) - end
}

func middleEllipsize(value string, width int) string {
	if width < 1 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width <= 3 {
		return string(runes[:width])
	}
	remaining := width - 3
	prefixLen := (remaining + 1) / 2
	suffixLen := remaining - prefixLen
	return string(runes[:prefixLen]) + "..." + string(runes[len(runes)-suffixLen:])
}

func optionFieldWidth(options []string) int {
	width := 0
	for _, option := range options {
		if len(option) > width {
			width = len(option)
		}
	}
	if width < 20 {
		width = 20
	}
	return width + 4
}

func parameterRequirementLabel(label string, required bool) string {
	if required {
		return label
	}
	return label + " (optional)"
}

func fixedWidthFieldLine(line string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(line)
	if len(runes) > width {
		return string(runes[:width])
	}
	if len(runes) < width {
		return line + strings.Repeat(" ", width-len(runes))
	}
	return line
}

func (m Model) constrainParameterFieldWidth(width int) int {
	maxWidth := m.popupBodyWidth(80) - inputActiveStyle.GetHorizontalFrameSize()
	if maxWidth < 1 {
		maxWidth = 1
	}
	if width < 1 {
		return 1
	}
	if width > maxWidth {
		return maxWidth
	}
	return width
}

func (m Model) constrainParameterFieldHeight(height int, bodyBeforeField string) int {
	if height < 1 {
		return 1
	}
	maxBodyLines := m.popupContentHeight()
	if maxBodyLines <= 0 {
		return height
	}
	if m.usesSharedPopupViewport() && maxBodyLines > 1 {
		maxBodyLines-- // reserve the shared panel viewport status row
	}
	usedLines := renderedLinesBeforeAppend(bodyBeforeField)
	maxRenderedFieldLines := maxBodyLines - usedLines
	minRenderedFieldLines := inputActiveStyle.GetVerticalFrameSize() + 1
	if maxRenderedFieldLines < minRenderedFieldLines {
		maxRenderedFieldLines = minRenderedFieldLines
	}
	maxHeight := maxRenderedFieldLines - inputActiveStyle.GetVerticalFrameSize()
	if maxHeight < 1 {
		maxHeight = 1
	}
	if height > maxHeight {
		return maxHeight
	}
	return height
}

func renderedLinesBeforeAppend(s string) int {
	if s == "" {
		return 0
	}
	lines := lipgloss.Height(s)
	if strings.HasSuffix(s, "\n") {
		lines--
	}
	if lines < 0 {
		return 0
	}
	return lines
}

// renderGenerateParams renders the parameter input modal for LSig types with creation params
func (m Model) renderGenerateParams() string {
	return m.renderParameterModal(m.forms.generateKeyType, "GENERATE", m.forms.generateError)
}

// renderGenerating renders the loading state while generating a key
func (m Model) renderGenerating() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Generating Key"))
	sb.WriteString("\n\n")

	keyType := getKeyTypeByIndex(m.forms.generateKeyType)
	sb.WriteString(fmt.Sprintf("Key Type: %s\n\n", displayKeyType(keyType)))

	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")

	return m.renderPopup(50, sb.String())
}

// renderImporting renders the loading state while importing a key
func (m Model) renderImporting() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Importing Key"))
	sb.WriteString("\n\n")

	keyType := getImportKeyTypeByIndex(m.forms.importKeyType)
	sb.WriteString(fmt.Sprintf("Key Type: %s\n\n", displayKeyType(keyType)))

	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")

	return m.renderPopup(50, sb.String())
}

// renderGenerateDisplay renders the key generation confirmation screen
func (m Model) renderGenerateDisplay() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Key Generated Successfully"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("%s: %s\n", m.keyIdentifierLabel(m.forms.generatedKeyType), m.forms.generatedAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", displayKeyType(m.forms.generatedKeyType)))
	sb.WriteString("\n")

	sb.WriteString(subtitleStyle.Render("Recovery material is stored encrypted in the signer keyfile."))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("Use encrypted backups for recovery."))
	sb.WriteString("\n")

	return m.renderPopup(75, sb.String())
}

// renderImportParams renders the parameter input modal for import when required.
func (m Model) renderImportParams() string {
	keyType := getImportKeyTypeByIndex(m.forms.importKeyType)
	return m.renderParameterModalForKeyType(keyType, "IMPORT", m.forms.importError)
}

// renderDeleting renders the loading state while deleting a key
func (m Model) renderDeleting() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Deleting Key"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("%s: %s\n\n", m.keyIdentifierLabel(m.del.keyType), m.del.address))

	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")

	return m.renderPopup(70, sb.String())
}

// renderDisplaceConfirm renders the displacement confirmation modal
func (m Model) renderDisplaceConfirm() string {
	var sb strings.Builder

	sb.WriteString(warningStyle.Render("DISPLACE EXISTING CLIENT"))
	sb.WriteString("\n\n")

	sb.WriteString("Another apadmin client is already connected.\n")
	sb.WriteString("Proceeding will disconnect it.\n\n")

	// Buttons - Cancel is default (safer)
	var cancelBtn, proceedBtn string
	if m.displaceConfirmFocus == 0 {
		cancelBtn = buttonActiveStyle.Render("> CANCEL")
		proceedBtn = buttonInactiveStyle.Render("  PROCEED")
	} else {
		cancelBtn = buttonInactiveStyle.Render("  CANCEL")
		proceedBtn = buttonActiveStyle.BorderForeground(lipgloss.Color("214")).Foreground(lipgloss.Color("214")).Render("> PROCEED")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Center, cancelBtn, "  ", proceedBtn)
	sb.WriteString(buttons)

	return m.renderPopup(60, sb.String())
}

// renderDeleteConfirm renders the delete confirmation dialog
func (m Model) renderDeleteConfirm() string {
	var sb strings.Builder

	sb.WriteString(errorStyle.Render("DELETE KEY"))
	sb.WriteString("\n\n")

	sb.WriteString("Are you sure you want to delete this key?\n\n")

	sb.WriteString(fmt.Sprintf("%s: %s\n", m.keyIdentifierLabel(m.del.keyType), m.del.address))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", displayKeyType(m.del.keyType)))
	sb.WriteString("\n")

	sb.WriteString(errorStyle.Render("WARNING: This action cannot be undone!"))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("Make sure you have created an encrypted backup if needed."))
	sb.WriteString("\n\n")

	// Buttons - Cancel is default (safer)
	var cancelBtn, deleteBtn string
	if m.del.focus == 0 {
		cancelBtn = buttonActiveStyle.Render("> CANCEL")
		deleteBtn = buttonInactiveStyle.Render("  DELETE")
	} else {
		cancelBtn = buttonInactiveStyle.Render("  CANCEL")
		deleteBtn = buttonActiveStyle.BorderForeground(lipgloss.Color("196")).Foreground(lipgloss.Color("196")).Render("> DELETE")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Center, cancelBtn, "  ", deleteBtn)
	sb.WriteString(buttons)

	return m.renderPopup(80, sb.String())
}

// renderRevokeTokenConfirm renders the token revocation confirmation dialog
func (m Model) renderRevokeTokenConfirm() string {
	var sb strings.Builder

	sb.WriteString(errorStyle.Render("REVOKE API TOKEN"))
	sb.WriteString("\n\n")

	sb.WriteString("This will generate a new API token and invalidate the current one.\n\n")

	sb.WriteString(errorStyle.Render("All connected clients will be disconnected."))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("Clients must obtain a new token using: request-token"))
	sb.WriteString("\n\n")

	// Buttons - Cancel is default (safer)
	var cancelBtn, revokeBtn string
	if m.admin.revokeTokenFocus == 0 {
		cancelBtn = buttonActiveStyle.Render("> CANCEL")
		revokeBtn = buttonInactiveStyle.Render("  REVOKE")
	} else {
		cancelBtn = buttonInactiveStyle.Render("  CANCEL")
		revokeBtn = buttonActiveStyle.BorderForeground(lipgloss.Color("196")).Foreground(lipgloss.Color("196")).Render("> REVOKE")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Center, cancelBtn, "  ", revokeBtn)
	sb.WriteString(buttons)

	return m.renderPopup(80, sb.String())
}

// renderLockConfirm renders the manual signer lock confirmation dialog.
func (m Model) renderLockConfirm() string {
	var sb strings.Builder

	sb.WriteString(warningStyle.Render("LOCK SIGNER"))
	sb.WriteString("\n\n")

	sb.WriteString("This will clear the unlocked key session from signer memory.\n")
	sb.WriteString("apadmin will stay open and return to the unlock screen.\n\n")

	var cancelBtn, lockBtn string
	if m.manualLock.focus == 0 {
		cancelBtn = buttonActiveStyle.Render("> CANCEL")
		lockBtn = buttonInactiveStyle.Render("  LOCK")
	} else {
		cancelBtn = buttonInactiveStyle.Render("  CANCEL")
		lockBtn = buttonActiveStyle.BorderForeground(lipgloss.Color("214")).Foreground(lipgloss.Color("214")).Render("> LOCK")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Center, cancelBtn, "  ", lockBtn)
	sb.WriteString(buttons)

	return m.renderPopup(70, sb.String())
}
