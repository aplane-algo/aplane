// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

// Form view rendering for import, generate, export, and delete operations.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/algorithm"
)

// renderExportConfirm renders the export confirmation screen
func (m Model) renderExportConfirm() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Confirm Export"))
	sb.WriteString("\n\n")

	// Warning
	sb.WriteString(errorStyle.Render("WARNING: You are about to export a private key mnemonic!"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Key Type: %s\n", m.exportConfirmKeyType))
	sb.WriteString(fmt.Sprintf("Address:  %s\n", m.exportConfirmAddress))
	sb.WriteString("\n")

	sb.WriteString(subtitleStyle.Render("Enter your passphrase to confirm:"))
	sb.WriteString("\n\n")

	// Passphrase input field (masked)
	confirmInputStyle := inputStyle
	if m.exportConfirmError != "" {
		confirmInputStyle = confirmInputStyle.BorderForeground(lipgloss.Color("196")) // Red on error
	}
	// Mask the passphrase with asterisks
	maskedInput := strings.Repeat("*", len(m.exportConfirmPassphrase))
	if maskedInput == "" {
		maskedInput = " " // Ensure field is visible even when empty
	}
	sb.WriteString(confirmInputStyle.Width(40).Render(maskedInput))
	sb.WriteString("\n")

	// Error message
	if m.exportConfirmError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(m.exportConfirmError))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("Enter: Confirm | Esc: Cancel"))

	return popupStyle.Width(75).Render(sb.String())
}

// renderExportDisplay renders the mnemonic export display
func (m Model) renderExportDisplay() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Mnemonic Export"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.exportedAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", m.exportedKeyType))
	sb.WriteString("\n")

	// Show creation parameters if present (needed for address re-derivation)
	if len(m.exportedParameters) > 0 {
		sb.WriteString(keyTypeStyle.Render("Creation Parameters (required for re-import):"))
		sb.WriteString("\n")
		// Use param spec for ordered, labeled display if available
		if spec := getParamSpecForKeyType(m.exportedKeyType); spec != nil {
			for _, paramDef := range spec.Params {
				if value, ok := m.exportedParameters[paramDef.Name]; ok {
					sb.WriteString(fmt.Sprintf("  %s: %s\n", paramDef.Label, value))
				}
			}
		} else {
			for key, value := range m.exportedParameters {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", key, value))
			}
		}
		sb.WriteString("\n")
	}

	// Warning
	sb.WriteString(errorStyle.Render("WARNING: SENSITIVE DATA"))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("Anyone with this phrase can recreate your private key!"))
	sb.WriteString("\n\n")

	// Mnemonic display
	sb.WriteString(fmt.Sprintf("%d-word recovery phrase:\n", m.exportedWordCount))
	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\n")
	sb.WriteString(m.exportedMnemonic)
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\n\n")

	sb.WriteString(helpStyle.Render("Enter/Esc/q: Close (clears from memory)"))

	return popupStyle.Width(75).Render(sb.String())
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
	displayMnemonic := m.importMnemonicInput
	if displayMnemonic == "" {
		displayMnemonic = "(enter recovery phrase words separated by spaces)"
	}

	// Highlight input area if focused
	inputContent := displayMnemonic
	if m.importFocus == 1 {
		inputContent += "_"
	}
	// Word wrap for long mnemonics
	if len(inputContent) > 60 {
		words := strings.Split(inputContent, " ")
		var lines []string
		var currentLine string
		for _, word := range words {
			if len(currentLine)+len(word)+1 > 60 {
				lines = append(lines, currentLine)
				currentLine = word
			} else if currentLine == "" {
				currentLine = word
			} else {
				currentLine += " " + word
			}
		}
		if currentLine != "" {
			lines = append(lines, currentLine)
		}
		inputContent = strings.Join(lines, "\n  ")
	}

	if m.importFocus == 1 {
		sb.WriteString(inputStyle.Render("  " + inputContent))
	} else {
		sb.WriteString(subtitleStyle.Render("  " + inputContent))
	}
	sb.WriteString("\n\n")

	// Word count indicator (dynamically determined by selected key type)
	wordCount := 0
	if m.importMnemonicInput != "" {
		wordCount = len(strings.Fields(m.importMnemonicInput))
	}
	expectedWords := getExpectedWordCount(m.importKeyType)
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
		sb.WriteString("\n\n")
	}

	sb.WriteString(helpStyle.Render("Tab: Next field | Enter: Submit | Esc: Cancel"))

	return popupStyle.Width(70).Render(sb.String())
}

// renderImportDisplay renders the key import confirmation screen
func (m Model) renderImportDisplay() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Key Imported Successfully"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.importedAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", m.importedKeyType))
	sb.WriteString("\n")

	sb.WriteString(helpStyle.Render("Press Enter, Space, Esc, or q to continue"))

	return popupStyle.Width(75).Render(sb.String())
}

// renderGenerateForm renders the key type selection form
func (m Model) renderGenerateForm() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Generate New Key"))
	sb.WriteString("\n\n")

	// Key type selection (dynamically built from registered algorithms)
	keyTypes := getKeyTypeOptionsWithDescription()
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

	// Key type description (dynamically generated)
	selectedKeyType := getKeyTypeByIndex(m.generateKeyType)
	if spec := getParamSpecForKeyType(selectedKeyType); spec != nil {
		sb.WriteString(subtitleStyle.Render(spec.Description))
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("(%d parameters to configure)", len(spec.Params))))
	} else {
		meta, err := algorithm.GetMetadata(selectedKeyType)
		if err == nil && meta != nil && meta.RequiresLogicSig() {
			sb.WriteString(subtitleStyle.Render(fmt.Sprintf("%s post-quantum key - requires logic sig for transactions", selectedKeyType)))
		} else {
			sb.WriteString(subtitleStyle.Render(fmt.Sprintf("Standard %s key - compatible with all Algorand tools", selectedKeyType)))
		}
	}
	sb.WriteString("\n\n")

	// Error message
	if m.generateError != "" {
		sb.WriteString(errorStyle.Render(m.generateError))
		sb.WriteString("\n\n")
	}

	sb.WriteString(helpStyle.Render("Up/Down: Select | Enter: Continue | Esc: Cancel"))

	return popupStyle.Width(70).Render(sb.String())
}

// renderGenerateParams renders the parameter input modal for LSig types with creation params
func (m Model) renderGenerateParams() string {
	var sb strings.Builder

	selectedKeyType := getKeyTypeByIndex(m.generateKeyType)
	spec := getParamSpecForKeyType(selectedKeyType)
	if spec == nil {
		return popupStyle.Width(70).Render("Error: parameters not available")
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
	maxVisibleParams := availableHeight / 4
	if maxVisibleParams < 2 {
		maxVisibleParams = 2
	}

	// Show scroll-up indicator if not at top
	if m.generateParamScrollOffset > 0 {
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("  ▲ %d more above", m.generateParamScrollOffset)))
		sb.WriteString("\n")
	}

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

		// Get current value or placeholder
		value := ""
		if m.genericLSigParams != nil {
			value = m.genericLSigParams[paramDef.Name]
		}
		if value == "" {
			value = getPlaceholderForType(paramDef.Type)
		}

		// Add cursor if focused
		displayValue := value
		if isFieldFocused && m.genericLSigParams != nil {
			displayValue = m.genericLSigParams[paramDef.Name] + "_"
		}

		// Pad to field width - use mode's byte length if available
		fieldWidth := getFieldWidthForType(paramDef.Type, paramDef.MaxLength)
		if len(paramDef.InputModes) > 1 && m.genericLSigParamModes != nil {
			modeIdx := m.genericLSigParamModes[paramDef.Name]
			if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) {
				mode := paramDef.InputModes[modeIdx]
				if mode.ByteLength > 0 {
					fieldWidth = mode.ByteLength * 2 // hex encoding
				}
			}
		}
		for len(displayValue) < fieldWidth {
			displayValue += " "
		}

		if isFieldFocused {
			sb.WriteString(inputActiveStyle.Render(displayValue))
		} else {
			sb.WriteString(inputInactiveStyle.Render(displayValue))
		}
		sb.WriteString("\n\n")
	}

	// Show scroll-down indicator if more below
	if endIdx < totalParams {
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("  ▼ %d more below", totalParams-endIdx)))
		sb.WriteString("\n")
	}

	// Generate button
	buttonFocus := len(params)
	var genBtn string
	if m.generateFocus == buttonFocus {
		genBtn = buttonActiveStyle.Render(fmt.Sprintf("> [ GENERATE %s ] <", strings.ToUpper(spec.DisplayName)))
	} else {
		genBtn = buttonInactiveStyle.Render(fmt.Sprintf("  [ GENERATE %s ]  ", strings.ToUpper(spec.DisplayName)))
	}
	sb.WriteString(genBtn)
	sb.WriteString("\n\n")

	// Error message
	if m.generateError != "" {
		sb.WriteString(errorStyle.Render(m.generateError))
		sb.WriteString("\n\n")
	}

	sb.WriteString(helpStyle.Render("Tab: Next | </> Switch mode | Enter: Generate | Esc: Back"))

	return popupStyle.Width(80).Render(sb.String())
}

// renderGenerating renders the loading state while generating a key
func (m Model) renderGenerating() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Generating Key"))
	sb.WriteString("\n\n")

	keyType := getKeyTypeByIndex(m.generateKeyType)
	sb.WriteString(fmt.Sprintf("Key Type: %s\n\n", keyType))

	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")

	return popupStyle.Width(50).Render(sb.String())
}

// renderImporting renders the loading state while importing a key
func (m Model) renderImporting() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Importing Key"))
	sb.WriteString("\n\n")

	keyType := getKeyTypeByIndex(m.importKeyType)
	sb.WriteString(fmt.Sprintf("Key Type: %s\n\n", keyType))

	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")

	return popupStyle.Width(50).Render(sb.String())
}

// renderGenerateDisplay renders the key generation confirmation screen
func (m Model) renderGenerateDisplay() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Key Generated Successfully"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.generatedAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", m.generatedKeyType))
	sb.WriteString("\n")

	sb.WriteString(subtitleStyle.Render("To see the mnemonic, hit (e)"))
	sb.WriteString("\n\n")

	sb.WriteString(helpStyle.Render("e: Show mnemonic | Enter/Esc/q: Continue"))

	return popupStyle.Width(75).Render(sb.String())
}

// renderImportParams renders the parameter input modal for import when required.
func (m Model) renderImportParams() string {
	var sb strings.Builder

	selectedKeyType := getKeyTypeByIndex(m.importKeyType)
	spec := getParamSpecForKeyType(selectedKeyType)
	if spec == nil {
		return popupStyle.Width(70).Render("Error: parameters not available")
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
	maxVisibleParams := availableHeight / 4
	if maxVisibleParams < 2 {
		maxVisibleParams = 2
	}

	// Show scroll-up indicator if not at top
	if m.generateParamScrollOffset > 0 {
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("  ▲ %d more above", m.generateParamScrollOffset)))
		sb.WriteString("\n")
	}

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
			if isFieldFocused {
				modeHint = fmt.Sprintf("  [</> to switch: %d/%d]", modeIdx+1, len(paramDef.InputModes))
			}
		}

		label := "  " + labelText + ":"
		if isFieldFocused {
			label = "> " + labelText + ":"
		}
		sb.WriteString(label)
		if modeHint != "" {
			sb.WriteString(subtitleStyle.Render(modeHint))
		}
		sb.WriteString("\n")

		value := ""
		if m.genericLSigParams != nil {
			value = m.genericLSigParams[paramDef.Name]
		}
		if value == "" {
			value = getPlaceholderForType(paramDef.Type)
		}

		displayValue := value
		if isFieldFocused && m.genericLSigParams != nil {
			displayValue = m.genericLSigParams[paramDef.Name] + "_"
		}

		fieldWidth := getFieldWidthForType(paramDef.Type, paramDef.MaxLength)
		if len(paramDef.InputModes) > 1 && m.genericLSigParamModes != nil {
			modeIdx := m.genericLSigParamModes[paramDef.Name]
			if modeIdx >= 0 && modeIdx < len(paramDef.InputModes) {
				mode := paramDef.InputModes[modeIdx]
				if mode.ByteLength > 0 {
					fieldWidth = mode.ByteLength * 2
				}
			}
		}
		for len(displayValue) < fieldWidth {
			displayValue += " "
		}

		if isFieldFocused {
			sb.WriteString(inputActiveStyle.Render(displayValue))
		} else {
			sb.WriteString(inputInactiveStyle.Render(displayValue))
		}
		sb.WriteString("\n\n")
	}

	// Show scroll-down indicator if more below
	if endIdx < totalParams {
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("  ▼ %d more below", totalParams-endIdx)))
		sb.WriteString("\n")
	}

	// Import button
	buttonFocus := len(params)
	var importBtn string
	if m.generateFocus == buttonFocus {
		importBtn = buttonActiveStyle.Render(fmt.Sprintf("> [ IMPORT %s ] <", strings.ToUpper(spec.DisplayName)))
	} else {
		importBtn = buttonInactiveStyle.Render(fmt.Sprintf("  [ IMPORT %s ]  ", strings.ToUpper(spec.DisplayName)))
	}
	sb.WriteString(importBtn)
	sb.WriteString("\n\n")

	if m.importError != "" {
		sb.WriteString(errorStyle.Render(m.importError))
		sb.WriteString("\n\n")
	}

	sb.WriteString(helpStyle.Render("Tab: Next | </> Switch mode | Enter: Import | Esc: Back"))

	return popupStyle.Width(80).Render(sb.String())
}

// renderDeleting renders the loading state while deleting a key
func (m Model) renderDeleting() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Deleting Key"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n\n", m.deleteAddress))

	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")

	return popupStyle.Width(70).Render(sb.String())
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
	sb.WriteString("\n\n")

	sb.WriteString(helpStyle.Render("y/n or Tab/Arrows: Switch | Enter: Confirm | Esc: Cancel"))

	return popupStyle.Width(60).Render(sb.String())
}

// renderDeleteConfirm renders the delete confirmation dialog
func (m Model) renderDeleteConfirm() string {
	var sb strings.Builder

	sb.WriteString(errorStyle.Render("DELETE KEY"))
	sb.WriteString("\n\n")

	sb.WriteString("Are you sure you want to delete this key?\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.deleteAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", m.deleteKeyType))
	sb.WriteString("\n")

	sb.WriteString(errorStyle.Render("WARNING: This action cannot be undone!"))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("Make sure you have backed up the mnemonic if needed."))
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
	sb.WriteString("\n\n")

	sb.WriteString(helpStyle.Render("Tab/Arrows: Switch | Enter: Confirm | Esc: Cancel"))

	return popupStyle.Width(80).Render(sb.String())
}
