// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Form view rendering for import, generate, and delete operations.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
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
	sb.WriteString(subtitleStyle.Render("A signer-managed backup archive will be written to the identity backup store."))
	sb.WriteString("\n\n")

	exportStyle := inputInactiveStyle
	confirmStyle := inputInactiveStyle
	if m.backupConfirmFocus == 0 {
		exportStyle = inputActiveStyle
	}
	if m.backupConfirmFocus == 1 {
		confirmStyle = inputActiveStyle
	}
	if m.backupConfirmError != "" {
		if m.backupConfirmFocus == 0 {
			exportStyle = exportStyle.BorderForeground(lipgloss.Color("196"))
		} else {
			confirmStyle = confirmStyle.BorderForeground(lipgloss.Color("196"))
		}
	}

	sb.WriteString("Export passphrase:\n")
	exportMasked := strings.Repeat("*", len(m.backupExportPassphrase))
	if exportMasked == "" {
		exportMasked = " "
	}
	sb.WriteString(exportStyle.Width(40).Render(exportMasked))
	sb.WriteString("\n\n")

	sb.WriteString("Confirm export passphrase:\n")
	confirmMasked := strings.Repeat("*", len(m.backupConfirmPassphrase))
	if confirmMasked == "" {
		confirmMasked = " "
	}
	sb.WriteString(confirmStyle.Width(40).Render(confirmMasked))
	sb.WriteString("\n")

	if m.backupConfirmError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(m.backupConfirmError))
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
	sb.WriteString(m.backupArchivePath)
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
		if i == m.importKeyType {
			prefix = "> "
		}
		if m.importFocus == 0 && i == m.importKeyType {
			sb.WriteString(selectedStyle.Render(prefix + kt))
		} else if i == m.importKeyType {
			sb.WriteString(keyTypeStyle.Render(prefix + kt))
		} else {
			sb.WriteString(subtitleStyle.Render(prefix + kt))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// Mnemonic input
	sb.WriteString("Mnemonic Phrase:\n")
	mnemonicInput := m.importMnemonicInput
	mnemonicInput.SetWidth(62)
	mnemonicInput.SetHeight(4)
	mnemonicInput.MaxHeight = 4
	if m.importFocus == 1 {
		_ = mnemonicInput.Focus()
		sb.WriteString(inputStyle.Width(64).Render(mnemonicInput.View()))
	} else {
		mnemonicInput.Blur()
		sb.WriteString(subtitleStyle.Render(mnemonicInput.View()))
	}
	sb.WriteString("\n\n")

	// Word count indicator (dynamically determined by selected key type)
	wordCount := 0
	if value := m.importMnemonicInput.Value(); value != "" {
		wordCount = len(strings.Fields(value))
	}
	expectedWords := getExpectedImportWordCount(m.importKeyType)
	wordCountStr := fmt.Sprintf("Words: %d/%d", wordCount, expectedWords)
	if wordCount == expectedWords {
		sb.WriteString(statusUnlockedStyle.Render(wordCountStr))
	} else {
		sb.WriteString(subtitleStyle.Render(wordCountStr))
	}
	sb.WriteString("\n\n")

	// Submit button
	var importBtn string
	if m.importFocus == 2 {
		importBtn = buttonActiveStyle.Render("IMPORT KEY")
	} else {
		importBtn = buttonInactiveStyle.Render("IMPORT KEY")
	}
	sb.WriteString(importBtn)
	sb.WriteString("\n\n")

	// Error message
	if m.importError != "" {
		sb.WriteString(errorStyle.Render(m.importError))
		sb.WriteString("\n")
	}

	return m.renderPopup(70, sb.String())
}

// renderImportDisplay renders the key import confirmation screen
func (m Model) renderImportDisplay() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Key Imported Successfully"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.importedAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", displayKeyType(m.importedKeyType)))
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
		if i == m.generateKeyType {
			prefix = "> "
		}
		if i == m.generateKeyType {
			sb.WriteString(selectedStyle.Render(prefix + kt))
		} else {
			sb.WriteString(subtitleStyle.Render(prefix + kt))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// Selected key type label.
	selectedKeyType := getKeyTypeByIndex(m.generateKeyType)
	sb.WriteString(subtitleStyle.Render(getKeyTypeSelectionLabel(selectedKeyType)))
	sb.WriteString("\n\n")

	// Error message
	if m.generateError != "" {
		sb.WriteString(errorStyle.Render(m.generateError))
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
	totalParams := len(params)

	// Calculate visible parameters based on terminal height
	reservedLines := 12 // title + button + help + error + margins
	availableHeight := m.height - reservedLines
	if availableHeight < 12 {
		availableHeight = 12
	}
	maxVisibleParams := availableHeight / 8
	if maxVisibleParams < 1 {
		maxVisibleParams = 1
	}

	sb.WriteString(scrollMoreAboveLine(m.generateParamScrollOffset))
	sb.WriteString("\n")

	// Calculate visible range
	startIdx := m.generateParamScrollOffset
	endIdx := startIdx + maxVisibleParams
	if endIdx > totalParams {
		endIdx = totalParams
	}

	// Render only visible parameter fields
	for i := startIdx; i < endIdx; i++ {
		paramDef := params[i]
		isFieldFocused := m.generateFocus == i

		// Determine label - use input mode label if multiple modes exist
		labelText := paramDef.Label
		var modeHint string
		if len(paramDef.InputModes) > 1 {
			modeIdx := 0
			if m.genericLSigParamModes != nil {
				modeIdx = m.genericLSigParamModes[paramDef.Name]
			}
			if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) {
				labelText = paramDef.InputModes[modeIdx].Label
			}
			// Show mode toggle hint when focused
			if isFieldFocused {
				modeHint = fmt.Sprintf("  [</> to switch: %d/%d]", modeIdx+1, len(paramDef.InputModes))
			}
		}
		if len(paramDef.Options) > 0 && isFieldFocused {
			optionIdx := indexOfOption(paramDef.Options, m.genericLSigParams[paramDef.Name])
			if optionIdx < 0 {
				optionIdx = 0
			}
			modeHint = fmt.Sprintf("  [</> to choose: %d/%d]", optionIdx+1, len(paramDef.Options))
		}

		// Label with focus indicator
		label := "  " + labelText + ":"
		if isFieldFocused {
			label = "> " + labelText + ":"
		}
		sb.WriteString(label)
		if modeHint != "" {
			sb.WriteString(subtitleStyle.Render(modeHint))
		}
		sb.WriteString("\n")

		// Pad to field width - use mode's byte length if available, but keep
		// the rendered input box inside the popup body.
		fieldWidth := getFieldWidthForType(paramDef.Type, paramDef.MaxLength)
		if len(paramDef.Options) > 0 {
			fieldWidth = optionFieldWidth(paramDef.Options)
		}
		if len(paramDef.InputModes) > 1 && m.genericLSigParamModes != nil {
			modeIdx := m.genericLSigParamModes[paramDef.Name]
			if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) {
				mode := paramDef.InputModes[modeIdx]
				if mode.ByteLength > 0 {
					fieldWidth = mode.ByteLength * 2 // hex encoding
				}
			}
		}
		fieldHeight := getFieldHeightForType(paramDef.Type)
		fieldWidth = m.constrainParameterFieldWidth(fieldWidth)
		fieldHeight = m.constrainParameterFieldHeight(fieldHeight, sb.String())

		value := ""
		if m.genericLSigParams != nil {
			value = m.genericLSigParams[paramDef.Name]
		}
		if value == "" {
			value = getPlaceholderForType(paramDef.Type)
		}

		lines := paramInputLines(value)
		if isFieldFocused && m.genericLSigParams != nil {
			currentLines := paramInputLines(m.genericLSigParams[paramDef.Name])
			currentLines[len(currentLines)-1] += "_"
			lines = currentLines
		}
		aboveCount, belowCount := 0, 0
		if isMultilineParamType(paramDef.Type) {
			offset := 0
			maxOffset := maxParamInputScrollOffset(lines, fieldHeight)
			if m.genericLSigParamScroll != nil {
				offset = m.genericLSigParamScroll[paramDef.Name]
			}
			if offset < 0 {
				offset = 0
			}
			if offset > maxOffset {
				offset = maxOffset
			}
			aboveCount = offset
			end := offset + fieldHeight
			if end > len(lines) {
				end = len(lines)
			}
			belowCount = len(lines) - end
			lines = append([]string(nil), lines[offset:end]...)
		}
		if len(lines) < fieldHeight {
			for len(lines) < fieldHeight {
				lines = append(lines, "")
			}
		} else if len(lines) > fieldHeight {
			lines = lines[:fieldHeight]
		}

		for i, line := range lines {
			lines[i] = fixedWidthFieldLine(line, fieldWidth)
		}
		displayValue := strings.Join(lines, "\n")

		if isFieldFocused {
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

	sb.WriteString(scrollMoreBelowLine(totalParams - endIdx))
	sb.WriteString("\n")

	// Action button
	buttonFocus := len(params)
	var btn string
	if m.generateFocus == buttonFocus {
		btn = buttonActiveStyle.Render(fmt.Sprintf("> [ %s %s ] <", buttonVerb, strings.ToUpper(spec.DisplayName)))
	} else {
		btn = buttonInactiveStyle.Render(fmt.Sprintf("  [ %s %s ]  ", buttonVerb, strings.ToUpper(spec.DisplayName)))
	}
	sb.WriteString(btn)
	sb.WriteString("\n\n")

	// Error message
	if errorMsg != "" {
		sb.WriteString(errorStyle.Render(errorMsg))
		sb.WriteString("\n\n")
	}

	return m.renderPopup(80, sb.String())
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
	return m.renderParameterModal(m.generateKeyType, "GENERATE", m.generateError)
}

// renderGenerating renders the loading state while generating a key
func (m Model) renderGenerating() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Generating Key"))
	sb.WriteString("\n\n")

	keyType := getKeyTypeByIndex(m.generateKeyType)
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

	keyType := getImportKeyTypeByIndex(m.importKeyType)
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

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.generatedAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", displayKeyType(m.generatedKeyType)))
	sb.WriteString("\n")

	sb.WriteString(subtitleStyle.Render("Recovery material is stored encrypted in the signer keyfile."))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("Use encrypted backups for recovery."))
	sb.WriteString("\n")

	return m.renderPopup(75, sb.String())
}

// renderImportParams renders the parameter input modal for import when required.
func (m Model) renderImportParams() string {
	keyType := getImportKeyTypeByIndex(m.importKeyType)
	return m.renderParameterModalForKeyType(keyType, "IMPORT", m.importError)
}

// renderDeleting renders the loading state while deleting a key
func (m Model) renderDeleting() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Deleting Key"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n\n", m.deleteAddress))

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

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.deleteAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", displayKeyType(m.deleteKeyType)))
	sb.WriteString("\n")

	sb.WriteString(errorStyle.Render("WARNING: This action cannot be undone!"))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("Make sure you have created an encrypted backup if needed."))
	sb.WriteString("\n\n")

	// Buttons - Cancel is default (safer)
	var cancelBtn, deleteBtn string
	if m.deleteConfirmFocus == 0 {
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
	if m.revokeTokenConfirmFocus == 0 {
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
	if m.manualLockConfirmFocus == 0 {
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
