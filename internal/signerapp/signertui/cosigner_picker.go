// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) isCosignerSelectorParam(keyType string, param lsigprovider.ParameterDef) bool {
	info, ok := findServerKeyType(keyType)
	if !ok || info.CosignerComponentKeyType == "" {
		return false
	}
	return param.Name == cosignerrefs.ParamCosignerName || param.Name == keytypes.ParameterCosignerPublicKey
}

func (m Model) compatibleCosignerChoices(componentKeyType string) []cosignerChoice {
	grouped := make(map[string]*cosignerChoice)
	for _, reference := range m.cosigner.references {
		if reference.KeyType != componentKeyType || reference.ComponentKey == "" || reference.Name == "" {
			continue
		}
		choice := grouped[reference.ComponentKey]
		if choice == nil {
			choice = &cosignerChoice{
				WitnessKeyID: reference.ComponentKey,
				KeyType:      reference.KeyType,
			}
			grouped[reference.ComponentKey] = choice
		}
		choice.Aliases = append(choice.Aliases, reference.Name)
	}

	choices := make([]cosignerChoice, 0, len(grouped))
	for _, choice := range grouped {
		sort.Slice(choice.Aliases, func(i, j int) bool {
			left := strings.ToLower(choice.Aliases[i])
			right := strings.ToLower(choice.Aliases[j])
			if left != right {
				return left < right
			}
			return choice.Aliases[i] < choice.Aliases[j]
		})
		choice.PrimaryAlias = choice.Aliases[0]
		choices = append(choices, *choice)
	}
	sort.Slice(choices, func(i, j int) bool {
		left := strings.ToLower(choices[i].PrimaryAlias)
		right := strings.ToLower(choices[j].PrimaryAlias)
		if left != right {
			return left < right
		}
		return choices[i].WitnessKeyID < choices[j].WitnessKeyID
	})
	return choices
}

func (m Model) openCosignerPicker(keyType, paramName string) (Model, string) {
	info, ok := findServerKeyType(keyType)
	if !ok || info.CosignerComponentKeyType == "" {
		return m, "Selected key type does not advertise a cosigner component key type"
	}
	if !m.cosigner.loaded {
		return m, "Cosigner references are still loading; try again"
	}
	choices := m.compatibleCosignerChoices(info.CosignerComponentKeyType)
	m.cosigner.paramName = paramName
	m.cosigner.returnView = m.viewState
	m.cosigner.requiredKeyType = info.CosignerComponentKeyType
	if len(choices) == 0 {
		// Nothing to choose from yet, so go straight to the setup file.
		return m.beginGenerationCosignerImport(false), ""
	}

	m.cosigner.choices = choices
	m.cosigner.selected = 0
	if current := m.forms.genericLSigParams[paramName]; current != "" {
		for index, choice := range choices {
			if choice.WitnessKeyID == current {
				m.cosigner.selected = index
				break
			}
		}
	}
	m.viewState = ViewCosignerPicker
	return m, ""
}

// Rows the account-creation picker offers after the imported references, so a
// setup file can be chosen without visiting the Cosigners manager first.
const (
	cosignerPickerUseFileRow = iota
	cosignerPickerPasteRow
	cosignerPickerActionRows
)

// beginGenerationCosignerImport opens the import form from account creation.
// The parameter, return view, and required key type chosen by the picker are
// kept so a successful import fills the account's cosigner field.
func (m Model) beginGenerationCosignerImport(paste bool) Model {
	requiredKeyType := m.cosigner.requiredKeyType
	m.clearCosignerImportTransient()
	m.cosigner.requiredKeyType = requiredKeyType
	m.cosigner.importPaste = paste
	m.cosigner.importFocus = 0
	m.cosigner.choices = nil
	m.viewState = ViewCosignerImportForm
	return m
}

func (m *Model) clearCosignerImportEnvelope() {
	m.cosigner.envelopeJSON = ""
	m.cosigner.previewWitnessID = ""
	m.cosigner.previewKeyType = ""
	m.cosigner.reuseAliases = nil
}

// referenceAliasesForWitness returns the local names that already hold the
// given public key, sorted for a stable display.
func (m Model) referenceAliasesForWitness(witnessKeyID, keyType string) []string {
	var aliases []string
	for _, reference := range m.cosigner.references {
		if reference.ComponentKey == witnessKeyID && reference.KeyType == keyType && reference.Name != "" {
			aliases = append(aliases, reference.Name)
		}
	}
	sort.Slice(aliases, func(i, j int) bool {
		left, right := strings.ToLower(aliases[i]), strings.ToLower(aliases[j])
		if left != right {
			return left < right
		}
		return aliases[i] < aliases[j]
	})
	return aliases
}

func (m *Model) clearCosignerImportTransient() {
	m.clearCosignerImportEnvelope()
	m.cosigner.importPaste = false
	m.cosigner.importJSON = ""
	m.cosigner.importPath = ""
	m.cosigner.importName = ""
	m.cosigner.importNameDefault = ""
	m.cosigner.importError = ""
	m.cosigner.requiredKeyType = ""
}

func (m *Model) clearCosignerWorkflowState() {
	m.cosigner.references = nil
	m.cosigner.loaded = false
	m.cosigner.choices = nil
	m.cosigner.selected = 0
	m.cosigner.paramName = ""
	m.cosigner.returnView = ViewKeyList
	m.clearCosignerImportTransient()
	m.cosigner.importFocus = 0
	m.cosigner.pendingKeyType = ""
	m.cosigner.pendingWitnessID = ""
	m.cosigner.managerSelected = 0
	m.cosigner.managerScroll = 0
	m.cosigner.managerStatus = ""
	m.cosigner.removeFocus = 0
	m.cosigner.generateTypeIndices = nil
	m.cosigner.generateTypeSelected = 0
	m.cosigner.generateFromManager = false
	m.cosigner.exportWitnessID = ""
	m.cosigner.exportPath = ""
	m.cosigner.exportError = ""
	m.cosigner.exportWrittenPath = ""
	m.cosigner.exportReturnView = ViewKeyDetails
	m.cosigner.exportFocus = 0
	m.cosigner.exportShowJSON = false
}

func (m Model) cancelCosignerImport() Model {
	m.clearCosignerImportTransient()
	m.viewState = m.cosigner.returnView
	return m
}

func (m Model) prepareCosignerImportReview() Model {
	path := strings.TrimSpace(m.cosigner.importPath)
	if !m.cosigner.importPaste && path == "" {
		m.cosigner.importError = "Cosigner key file is required"
		return m
	}
	if !m.cosigner.importPaste && path == "-" {
		m.cosigner.importError = "The interactive TUI requires a file path; use batch apadmin cosigner import - <name> for stdin"
		return m
	}
	data := []byte(m.cosigner.importJSON)
	var err error
	if !m.cosigner.importPaste {
		data, err = apadminapp.ReadCosignerPublicEnvelope(path, nil)
		if err != nil {
			m.cosigner.importError = err.Error()
			return m
		}
	}
	reference, err := witness.ParsePublicReference(data)
	if err != nil {
		m.cosigner.importError = fmt.Sprintf("invalid cosigner key file: %v", err)
		return m
	}
	name := strings.TrimSpace(m.cosigner.importName)
	if name == m.cosigner.importNameDefault {
		name = ""
	}
	if name == "" && !m.cosigner.importPaste {
		name = cosignerImportNameFromPath(path)
	}
	if name == "" {
		name = suggestedCosignerReferenceName(reference.WitnessKeyID)
	}
	if !m.hasCustomCosignerImportName() {
		m.cosigner.importNameDefault = name
	}
	name, err = cosignerrefs.NormalizeName(name)
	if err != nil {
		m.cosigner.importError = err.Error()
		return m
	}
	m.cosigner.importName = name
	if m.cosigner.requiredKeyType != "" && reference.KeyType != m.cosigner.requiredKeyType {
		m.cosigner.importError = fmt.Sprintf(
			"public witness key type %s is incompatible; this account requires %s",
			reference.KeyType,
			m.cosigner.requiredKeyType,
		)
		return m
	}
	witnessJSON, err := witness.MarshalPublicReference(reference)
	if err != nil {
		m.cosigner.importError = fmt.Sprintf("invalid public witness envelope: %v", err)
		return m
	}
	m.cosigner.reuseAliases = nil
	if m.cosigner.paramName != "" {
		// Account creation reuses a key that is already imported instead of
		// importing it again under another name.
		m.cosigner.reuseAliases = m.referenceAliasesForWitness(reference.WitnessKeyID, reference.KeyType)
	}
	m.cosigner.envelopeJSON = string(witnessJSON)
	m.cosigner.previewWitnessID = reference.WitnessKeyID
	m.cosigner.previewKeyType = reference.KeyType
	m.cosigner.importError = ""
	m.viewState = ViewCosignerImportReview
	return m
}

func (m Model) handleCosignerImportFormKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Treat bracketed paste as data before interpreting any navigation keys.
	if m.cosigner.importPaste && msg.Paste {
		switch m.cosigner.importFocus {
		case 0:
			value := string(msg.Runes)
			if len(value) > apadminapp.MaxCosignerPublicEnvelopeBytes {
				m.cosigner.importJSON = ""
				m.cosigner.importError = "JSON exceeds the 64 KiB limit; paste a smaller cosigner key document"
				return m, nil
			}
			m.cosigner.importJSON = value
			m = m.suggestCosignerImportNameFromDocument([]byte(value))
			m.cosigner.importError = ""
		case 1:
			m.cosigner.importName += string(msg.Runes)
			m.cosigner.importError = ""
		}
		return m, nil
	}
	switch msg.String() {
	case "esc":
		return m.cancelCosignerImport(), nil
	case "tab", "down":
		m = m.suggestCosignerImportNameFromPath()
		m.cosigner.importFocus = (m.cosigner.importFocus + 1) % 3
		return m, nil
	case "shift+tab", "up":
		m.cosigner.importFocus = (m.cosigner.importFocus + 2) % 3
		return m, nil
	case "backspace", "delete":
		switch m.cosigner.importFocus {
		case 0:
			if m.cosigner.importPaste {
				m.cosigner.importJSON = ""
			} else {
				m.cosigner.importPath = trimLastRune(m.cosigner.importPath)
			}
		case 1:
			m.cosigner.importName = trimLastRune(m.cosigner.importName)
		}
		m.cosigner.importError = ""
		return m, nil
	case "enter":
		if m.cosigner.importFocus < 2 {
			m = m.suggestCosignerImportNameFromPath()
			m.cosigner.importFocus++
			return m, nil
		}
		return m.prepareCosignerImportReview(), nil
	}
	if msg.Type == tea.KeyRunes {
		value := string(msg.Runes)
		switch m.cosigner.importFocus {
		case 0:
			if !m.cosigner.importPaste {
				m.cosigner.importPath += value
			}
		case 1:
			m.cosigner.importName += value
		}
		m.cosigner.importError = ""
	}
	return m, nil
}

func (m Model) suggestCosignerImportNameFromPath() Model {
	if m.cosigner.importPaste || m.cosigner.importFocus != 0 || m.hasCustomCosignerImportName() {
		return m
	}
	m.cosigner.importName = cosignerImportNameFromPath(m.cosigner.importPath)
	m.cosigner.importNameDefault = m.cosigner.importName
	return m
}

func cosignerImportNameFromPath(path string) string {
	path = strings.TrimSpace(path)
	base := filepath.Base(path)
	if strings.HasSuffix(strings.ToLower(base), cosignerKeyFileSuffix) {
		base = base[:len(base)-len(cosignerKeyFileSuffix)]
	} else {
		base = strings.TrimSuffix(base, filepath.Ext(base))
	}
	if name := sanitizeCosignerReferenceNameSuggestion(base); name != "" {
		return name
	}
	return ""
}

func (m Model) suggestCosignerImportNameFromDocument(data []byte) Model {
	if m.hasCustomCosignerImportName() {
		return m
	}
	m.cosigner.importName = ""
	m.cosigner.importNameDefault = ""
	reference, err := witness.ParsePublicReference(data)
	if err == nil {
		m.cosigner.importName = suggestedCosignerReferenceName(reference.WitnessKeyID)
		m.cosigner.importNameDefault = m.cosigner.importName
	}
	return m
}

func (m Model) hasCustomCosignerImportName() bool {
	return strings.TrimSpace(m.cosigner.importName) != "" && m.cosigner.importName != m.cosigner.importNameDefault
}

func suggestedCosignerReferenceName(witnessKeyID string) string {
	compact := strings.ToLower(strings.TrimSpace(witnessKeyID))
	if len(compact) > 10 {
		compact = compact[:10]
	}
	if compact == "" {
		return "cosigner"
	}
	return "cosigner-" + compact
}

func sanitizeCosignerReferenceNameSuggestion(value string) string {
	base := strings.ToLower(strings.TrimSpace(value))
	var suggestion strings.Builder
	lastDash := false
	for _, r := range base {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-'
		if valid {
			suggestion.WriteRune(r)
			lastDash = r == '-'
			continue
		}
		if suggestion.Len() > 0 && !lastDash {
			suggestion.WriteByte('-')
			lastDash = true
		}
	}
	name := strings.Trim(suggestion.String(), "._-")
	for strings.Contains(name, "..") {
		name = strings.ReplaceAll(name, "..", ".")
	}
	if normalized, err := cosignerrefs.NormalizeName(name); err == nil {
		return normalized
	}
	return ""
}

func trimLastRune(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return value
	}
	return string(runes[:len(runes)-1])
}

func (m Model) handleCosignerImportReviewKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		m.viewState = ViewCosignerImportForm
	case "enter", " ", "y":
		if len(m.cosigner.reuseAliases) > 0 {
			return m.useExistingCosignerReference(), nil
		}
		return m.submitCosignerImportReview()
	}
	return m, nil
}

// useExistingCosignerReference fills the account's cosigner field with a key
// that is already imported and returns to the generation form. Nothing is
// imported and no reference is rebound.
func (m Model) useExistingCosignerReference() Model {
	if m.forms.genericLSigParams == nil {
		m.forms.genericLSigParams = make(map[string]string)
	}
	m.forms.genericLSigParams[m.cosigner.paramName] = m.cosigner.previewWitnessID
	m.forms.generateError = ""
	m.viewState = m.cosigner.returnView
	m.clearCosignerImportTransient()
	m.cosigner.paramName = ""
	return m
}

func (m Model) submitCosignerImportReview() (tea.Model, tea.Cmd) {
	if m.cosigner.envelopeJSON == "" {
		m.cosigner.importError = "Cosigner key JSON is no longer available; choose it again"
		m.viewState = ViewCosignerImportForm
		return m, nil
	}
	m.cosigner.importError = ""
	m.viewState = ViewCosignerImporting
	return m, tea.Batch(
		m.sendImportCosignerReferenceCmd(m.cosigner.importName, m.cosigner.envelopeJSON),
		m.waitForMessageCmd(),
	)
}

func (m Model) completeCosignerImport(
	reference CosignerReferenceInfo,
) (tea.Model, tea.Cmd) {
	managerImport := m.cosigner.returnView == ViewCosignerReferences && m.cosigner.paramName == ""
	m.cosigner.importJSON = ""
	m.cosigner.importPaste = false
	m.clearCosignerImportEnvelope()
	m.cosigner.importError = ""
	if managerImport {
		m.cosigner.managerStatus = "Imported " + reference.Name + ". Next: Generate account; configure its cosigner connection in apshell with endpoints add."
		m.cosigner.returnView = ViewKeyList
		m.viewState = ViewCosignerReferences
		return m, tea.Batch(
			m.waitForMessageCmd(),
			m.sendListCosignerReferencesCmd(),
			m.sendListKeyTypesCmd(),
		)
	}
	m.cosigner.pendingKeyType = getKeyTypeByIndex(m.forms.generateKeyType)
	m.cosigner.pendingWitnessID = reference.ComponentKey
	m.viewState = ViewGenerateParams
	return m, tea.Batch(
		m.waitForMessageCmd(),
		m.sendListCosignerReferencesCmd(),
		m.sendListKeyTypesCmd(),
	)
}

func groupedWitnessKeyID(id string) string {
	return witness.GroupedID(id)
}

func (m Model) handleCosignerPickerKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.viewState = m.cosigner.returnView
		m.cosigner.choices = nil
		m.cosigner.paramName = ""
		m.cosigner.requiredKeyType = ""
		return m, nil
	case "up", "k":
		if m.cosigner.selected > 0 {
			m.cosigner.selected--
		}
	case "down", "j":
		if m.cosigner.selected+1 < len(m.cosigner.choices)+cosignerPickerActionRows {
			m.cosigner.selected++
		}
	case "enter", " ":
		switch m.cosigner.selected - len(m.cosigner.choices) {
		case cosignerPickerUseFileRow:
			return m.beginGenerationCosignerImport(false), nil
		case cosignerPickerPasteRow:
			return m.beginGenerationCosignerImport(true), nil
		}
		if m.cosigner.selected < 0 || m.cosigner.selected >= len(m.cosigner.choices) {
			return m, nil
		}
		choice := m.cosigner.choices[m.cosigner.selected]
		if m.forms.genericLSigParams == nil {
			m.forms.genericLSigParams = make(map[string]string)
		}
		m.forms.genericLSigParams[m.cosigner.paramName] = choice.WitnessKeyID
		m.viewState = m.cosigner.returnView
		m.cosigner.choices = nil
		m.cosigner.paramName = ""
		m.cosigner.requiredKeyType = ""
		m.forms.generateError = ""
		return m, nil
	}
	return m, nil
}

func (m Model) cosignerSelectionDisplay(witnessKeyID string) string {
	if witnessKeyID == "" {
		return "Choose an enrolled cosigner"
	}
	for _, choice := range m.choicesForAllReferences() {
		if choice.WitnessKeyID == witnessKeyID {
			return fmt.Sprintf("%s  %s", choice.PrimaryAlias, apadminapp.CompactWitnessKeyID(witnessKeyID))
		}
	}
	return apadminapp.CompactWitnessKeyID(witnessKeyID)
}

func (m Model) choicesForAllReferences() []cosignerChoice {
	seenTypes := make(map[string]bool)
	var choices []cosignerChoice
	for _, reference := range m.cosigner.references {
		if seenTypes[reference.KeyType] {
			continue
		}
		seenTypes[reference.KeyType] = true
		choices = append(choices, m.compatibleCosignerChoices(reference.KeyType)...)
	}
	return choices
}

func (m Model) renderCosignerPicker() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Choose Cosigner"))
	body.WriteString("\n\n")
	body.WriteString(subtitleStyle.Render("Select an imported cosigner key for this account, or use the setup file exported by the cosigner."))
	body.WriteString("\n\n")
	for index, choice := range m.cosigner.choices {
		prefix := "  "
		if index == m.cosigner.selected {
			prefix = "> "
		}
		row := fmt.Sprintf("%s%s  %s", prefix, choice.PrimaryAlias, apadminapp.CompactWitnessKeyID(choice.WitnessKeyID))
		if len(choice.Aliases) > 1 {
			row += fmt.Sprintf("  (%d aliases)", len(choice.Aliases))
		}
		if index == m.cosigner.selected {
			body.WriteString(selectedStyle.Render(row))
		} else {
			body.WriteString(row)
		}
		body.WriteString("\n")
	}
	body.WriteString("\n")
	for action, label := range [cosignerPickerActionRows]string{
		cosignerPickerUseFileRow: "Use setup file...",
		cosignerPickerPasteRow:   "Paste public JSON...",
	} {
		row := "  " + label
		if m.cosigner.selected == len(m.cosigner.choices)+action {
			row = selectedStyle.Render("> " + label)
		}
		body.WriteString(row + "\n")
	}
	body.WriteString("\n")
	body.WriteString(helpStyle.Render("↑/↓ navigate  Enter select  Esc cancel"))
	body.WriteString("\n")
	return m.renderPopup(80, body.String())
}

func (m Model) renderCosignerImportForm() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Import Cosigner Key"))
	body.WriteString("\n\n")
	if m.cosigner.importPaste {
		body.WriteString(subtitleStyle.Render("Paste the setup JSON exported by the cosigner node (up to 64 KiB)."))
	} else {
		body.WriteString(subtitleStyle.Render("Choose the setup file exported by the cosigner node."))
	}
	body.WriteString("\n\n")

	pathStyle := inputInactiveStyle
	nameStyle := inputInactiveStyle
	if m.cosigner.importFocus == 0 {
		pathStyle = inputActiveStyle
	}
	if m.cosigner.importFocus == 1 {
		nameStyle = inputActiveStyle
	}
	if m.cosigner.importPaste {
		body.WriteString("Cosigner key JSON:\n")
		preview := "Paste JSON here"
		if m.cosigner.importJSON != "" {
			preview = fmt.Sprintf("%d bytes captured; paste again to replace", len(m.cosigner.importJSON))
		}
		body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(preview))
		body.WriteString("\n" + helpStyle.Render("Use your terminal paste shortcut. Backspace/Delete clears the JSON."))
	} else {
		body.WriteString("Cosigner key file:\n")
		body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(m.cosigner.importPath))
	}
	body.WriteString("\n\nReference name:\n")
	body.WriteString(nameStyle.Width(m.constrainParameterFieldWidth(40)).Render(m.cosigner.importName))
	body.WriteString("\n" + helpStyle.Render("Defaults from the filename or Witness Key ID; edit if needed."))
	body.WriteString("\n\n")
	button := buttonInactiveStyle.Render("REVIEW COSIGNER KEY")
	if m.cosigner.importFocus == 2 {
		button = buttonActiveStyle.Render("REVIEW COSIGNER KEY")
	}
	body.WriteString(button)
	body.WriteString("\n")
	if m.cosigner.importError != "" {
		body.WriteString("\n")
		body.WriteString(errorStyle.Render(m.cosigner.importError))
		body.WriteString("\n")
	}
	return m.renderPopup(80, body.String())
}

func (m Model) renderCosignerImportReview() string {
	if len(m.cosigner.reuseAliases) > 0 {
		return m.renderCosignerReuseReview()
	}
	var body strings.Builder
	body.WriteString(titleStyle.Render("Review Cosigner Key"))
	body.WriteString("\n\n")
	body.WriteString("Store this public cosigner key as " + m.cosigner.importName + "\n")
	body.WriteString("Key type: " + m.cosigner.previewKeyType + "\n\n")
	body.WriteString("Witness Key ID (compare the complete value):\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.cosigner.previewWitnessID), m.popupBodyWidth(90)))
	body.WriteString("\n\n")
	body.WriteString("\n")
	button := buttonActiveStyle.Render("IMPORT")
	body.WriteString(button)
	body.WriteString("\n")
	body.WriteString(warningStyle.Render("Compare the complete Witness Key ID before importing."))
	if m.cosigner.paramName != "" {
		body.WriteString("\n" + helpStyle.Render("The imported key stays in Cosigners and is reused next time, even if account creation is cancelled."))
	}
	if m.cosigner.importError != "" {
		body.WriteString("\n\n")
		body.WriteString(errorStyle.Render(m.cosigner.importError))
	}
	body.WriteString("\n")
	return m.renderPopup(90, body.String())
}

// renderCosignerReuseReview is shown when account creation chose a setup file
// whose key is already imported. It offers the existing reference rather than
// a second import.
func (m Model) renderCosignerReuseReview() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Cosigner Key Already Imported"))
	body.WriteString("\n\n")
	primary := m.cosigner.reuseAliases[0]
	body.WriteString("This key is already imported as " + primary + ".")
	if others := len(m.cosigner.reuseAliases) - 1; others > 0 {
		body.WriteString(fmt.Sprintf(" (%d other name(s) refer to the same key.)", others))
	}
	body.WriteString("\nKey type: " + m.cosigner.previewKeyType + "\n\n")
	body.WriteString("Witness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.cosigner.previewWitnessID), m.popupBodyWidth(90)))
	body.WriteString("\n\n")
	body.WriteString(buttonActiveStyle.Render("USE " + strings.ToUpper(primary)))
	body.WriteString("\n")
	body.WriteString(helpStyle.Render("Nothing is imported or renamed. Esc goes back."))
	body.WriteString("\n")
	return m.renderPopup(90, body.String())
}

func (m Model) renderCosignerImporting() string {
	return m.renderPopup(60, titleStyle.Render("Importing Cosigner Key")+"\n\n"+subtitleStyle.Render("Please wait...")+"\n")
}
