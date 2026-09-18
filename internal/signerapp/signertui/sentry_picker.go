// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) isSentrySelectorParam(keyType string, param lsigprovider.ParameterDef) bool {
	info, ok := findServerKeyType(keyType)
	if !ok || info.SentryComponentKeyType == "" {
		return false
	}
	return param.Name == sentryrefs.ParamSentryName || param.Name == keytypes.ParameterSentryPublicKey
}

func (m Model) compatibleSentryChoices(componentKeyType string) []sentryChoice {
	grouped := make(map[string]*sentryChoice)
	for _, reference := range m.sentry.references {
		if reference.KeyType != componentKeyType || reference.ComponentKey == "" || reference.Name == "" {
			continue
		}
		choice := grouped[reference.ComponentKey]
		if choice == nil {
			choice = &sentryChoice{
				WitnessKeyID: reference.ComponentKey,
				KeyType:      reference.KeyType,
			}
			grouped[reference.ComponentKey] = choice
		}
		choice.Aliases = append(choice.Aliases, reference.Name)
	}

	choices := make([]sentryChoice, 0, len(grouped))
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

func (m Model) openSentryPicker(keyType, paramName string) (Model, string) {
	info, ok := findServerKeyType(keyType)
	if !ok || info.SentryComponentKeyType == "" {
		return m, "Selected key type does not advertise a sentry component key type"
	}
	if !m.sentry.loaded {
		return m, "Sentry references are still loading; try again"
	}
	choices := m.compatibleSentryChoices(info.SentryComponentKeyType)
	if len(choices) == 0 {
		m.clearSentryImportTransient()
		m.sentry.importPath = ""
		m.sentry.importName = ""
		m.sentry.importFocus = 0
		m.sentry.importError = ""
		m.sentry.paramName = paramName
		m.sentry.returnView = m.viewState
		m.sentry.requiredKeyType = info.SentryComponentKeyType
		m.clearSentryImportEnvelope()
		m.viewState = ViewSentryImportForm
		return m, ""
	}

	m.sentry.choices = choices
	m.sentry.selected = 0
	m.sentry.paramName = paramName
	m.sentry.returnView = m.viewState
	if current := m.forms.genericLSigParams[paramName]; current != "" {
		for index, choice := range choices {
			if choice.WitnessKeyID == current {
				m.sentry.selected = index
				break
			}
		}
	}
	m.viewState = ViewSentryPicker
	return m, ""
}

func (m *Model) clearSentryImportEnvelope() {
	m.sentry.envelopeJSON = ""
	m.sentry.previewWitnessID = ""
	m.sentry.previewKeyType = ""
	m.sentry.previewEndpoint = nil
}

func (m *Model) clearSentryImportTransient() {
	m.clearSentryImportEnvelope()
	m.sentry.importPaste = false
	m.sentry.importJSON = ""
	m.sentry.importPath = ""
	m.sentry.importName = ""
	m.sentry.importError = ""
	m.sentry.requiredKeyType = ""
}

func (m *Model) clearSentryWorkflowState() {
	m.sentry.references = nil
	m.sentry.loaded = false
	m.sentry.choices = nil
	m.sentry.selected = 0
	m.sentry.paramName = ""
	m.sentry.returnView = ViewKeyList
	m.clearSentryImportTransient()
	m.sentry.importFocus = 0
	m.sentry.pendingKeyType = ""
	m.sentry.pendingWitnessID = ""
	m.sentry.managerSelected = 0
	m.sentry.managerScroll = 0
	m.sentry.managerStatus = ""
	m.sentry.removeFocus = 0
	m.sentry.generateTypeIndices = nil
	m.sentry.generateTypeSelected = 0
	m.sentry.generateFromManager = false
	m.sentry.exportWitnessID = ""
	m.sentry.exportPath = ""
	m.sentry.exportError = ""
	m.sentry.exportEndpoint = nil
	m.sentry.exportIncludeEndpoint = false
	m.sentry.exportEndpointError = ""
	m.sentry.exportWrittenPath = ""
	m.sentry.exportReturnView = ViewKeyDetails
	m.sentry.exportFocus = 0
	m.sentry.exportShowJSON = false
}

func (m Model) cancelSentryImport() Model {
	m.clearSentryImportTransient()
	m.viewState = m.sentry.returnView
	return m
}

func (m Model) prepareSentryImportReview() Model {
	path := strings.TrimSpace(m.sentry.importPath)
	name := strings.TrimSpace(m.sentry.importName)
	if !m.sentry.importPaste && path == "" {
		m.sentry.importError = "Public envelope path is required"
		return m
	}
	if !m.sentry.importPaste && path == "-" {
		m.sentry.importError = "The interactive TUI requires a file path; use batch apadmin sentry import - <name> for stdin"
		return m
	}
	if name == "" {
		m.sentry.importError = "Suggested name is required"
		return m
	}
	name, err := sentryrefs.NormalizeName(name)
	if err != nil {
		m.sentry.importError = err.Error()
		return m
	}
	m.sentry.importName = name
	data := []byte(m.sentry.importJSON)
	if !m.sentry.importPaste {
		data, err = apadminapp.ReadSentryPublicEnvelope(path, nil)
		if err != nil {
			m.sentry.importError = err.Error()
			return m
		}
	}
	artifact, err := enrollment.ParseArtifact(data)
	if err != nil {
		m.sentry.importError = fmt.Sprintf("invalid sentry enrollment artifact: %v", err)
		return m
	}
	reference := artifact.Witness
	if m.sentry.requiredKeyType != "" && reference.KeyType != m.sentry.requiredKeyType {
		m.sentry.importError = fmt.Sprintf(
			"public witness key type %s is incompatible; this account requires %s",
			reference.KeyType,
			m.sentry.requiredKeyType,
		)
		return m
	}
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		m.sentry.importError = fmt.Sprintf("invalid public witness envelope: %v", err)
		return m
	}
	m.sentry.envelopeJSON = string(witnessJSON)
	m.sentry.previewWitnessID = reference.WitnessKeyID
	m.sentry.previewKeyType = reference.KeyType
	m.sentry.previewEndpoint = artifact.Endpoint
	m.sentry.importError = ""
	m.viewState = ViewSentryImportReview
	return m
}

func (m Model) handleSentryImportFormKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Treat bracketed paste as data before interpreting any navigation keys.
	if m.sentry.importPaste && msg.Paste {
		switch m.sentry.importFocus {
		case 0:
			value := string(msg.Runes)
			if len(value) > enrollment.MaxEnvelopeBytes {
				m.sentry.importJSON = ""
				m.sentry.importError = "JSON exceeds the 64 KiB limit; paste a smaller enrollment document"
				return m, nil
			}
			m.sentry.importJSON = value
			m.sentry.importError = ""
		case 1:
			m.sentry.importName += string(msg.Runes)
			m.sentry.importError = ""
		}
		return m, nil
	}
	switch msg.String() {
	case "esc":
		return m.cancelSentryImport(), nil
	case "tab", "down":
		m = m.suggestSentryImportNameFromPath()
		m.sentry.importFocus = (m.sentry.importFocus + 1) % 3
		return m, nil
	case "shift+tab", "up":
		m.sentry.importFocus = (m.sentry.importFocus + 2) % 3
		return m, nil
	case "backspace", "delete":
		switch m.sentry.importFocus {
		case 0:
			if m.sentry.importPaste {
				m.sentry.importJSON = ""
			} else {
				m.sentry.importPath = trimLastRune(m.sentry.importPath)
			}
		case 1:
			m.sentry.importName = trimLastRune(m.sentry.importName)
		}
		m.sentry.importError = ""
		return m, nil
	case "enter":
		if m.sentry.importFocus < 2 {
			m = m.suggestSentryImportNameFromPath()
			m.sentry.importFocus++
			return m, nil
		}
		return m.prepareSentryImportReview(), nil
	}
	if msg.Type == tea.KeyRunes {
		value := string(msg.Runes)
		switch m.sentry.importFocus {
		case 0:
			if !m.sentry.importPaste {
				m.sentry.importPath += value
			}
		case 1:
			m.sentry.importName += value
		}
		m.sentry.importError = ""
	}
	return m, nil
}

func (m Model) suggestSentryImportNameFromPath() Model {
	if m.sentry.importPaste || m.sentry.importFocus != 0 || strings.TrimSpace(m.sentry.importName) != "" {
		return m
	}
	path := strings.TrimSpace(m.sentry.importPath)
	base := filepath.Base(path)
	if strings.HasSuffix(strings.ToLower(base), sentryEnrollmentFileSuffix) {
		base = base[:len(base)-len(sentryEnrollmentFileSuffix)]
	} else {
		base = strings.TrimSuffix(base, filepath.Ext(base))
	}
	if name := sanitizeSentryReferenceNameSuggestion(base); name != "" {
		m.sentry.importName = name
	}
	return m
}

func sanitizeSentryReferenceNameSuggestion(value string) string {
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
	if normalized, err := sentryrefs.NormalizeName(name); err == nil {
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

func (m Model) handleSentryImportReviewKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		m.viewState = ViewSentryImportForm
	case "enter", " ", "y":
		return m.submitSentryImportReview()
	}
	return m, nil
}

func (m Model) submitSentryImportReview() (tea.Model, tea.Cmd) {
	if m.sentry.envelopeJSON == "" {
		m.sentry.importError = "Public envelope is no longer available; choose it again"
		m.viewState = ViewSentryImportForm
		return m, nil
	}
	m.sentry.importError = ""
	m.viewState = ViewSentryImporting
	return m, tea.Batch(
		m.sendImportSentryReferenceCmd(m.sentry.importName, m.sentry.envelopeJSON),
		m.waitForMessageCmd(),
	)
}

func (m Model) completeSentryImport(
	reference SentryReferenceInfo,
) (tea.Model, tea.Cmd) {
	managerImport := m.sentry.returnView == ViewSentryReferences && m.sentry.paramName == ""
	m.sentry.importJSON = ""
	m.sentry.importPaste = false
	m.clearSentryImportEnvelope()
	m.sentry.importError = ""
	if managerImport {
		m.sentry.managerStatus = "Imported " + reference.Name
		m.sentry.returnView = ViewKeyList
		m.viewState = ViewSentryReferences
		return m, tea.Batch(
			m.waitForMessageCmd(),
			m.sendListSentryReferencesCmd(),
			m.sendListKeyTypesCmd(),
		)
	}
	m.sentry.pendingKeyType = getKeyTypeByIndex(m.forms.generateKeyType)
	m.sentry.pendingWitnessID = reference.ComponentKey
	m.viewState = ViewGenerateParams
	return m, tea.Batch(
		m.waitForMessageCmd(),
		m.sendListSentryReferencesCmd(),
		m.sendListKeyTypesCmd(),
	)
}

func groupedWitnessKeyID(id string) string {
	return witness.GroupedID(id)
}

func (m Model) handleSentryPickerKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.viewState = m.sentry.returnView
		m.sentry.choices = nil
		m.sentry.paramName = ""
		return m, nil
	case "up", "k":
		if m.sentry.selected > 0 {
			m.sentry.selected--
		}
	case "down", "j":
		if m.sentry.selected+1 < len(m.sentry.choices) {
			m.sentry.selected++
		}
	case "enter", " ":
		if m.sentry.selected < 0 || m.sentry.selected >= len(m.sentry.choices) {
			return m, nil
		}
		choice := m.sentry.choices[m.sentry.selected]
		if m.forms.genericLSigParams == nil {
			m.forms.genericLSigParams = make(map[string]string)
		}
		m.forms.genericLSigParams[m.sentry.paramName] = choice.WitnessKeyID
		m.viewState = m.sentry.returnView
		m.sentry.choices = nil
		m.sentry.paramName = ""
		m.forms.generateError = ""
		return m, nil
	}
	return m, nil
}

func (m Model) sentrySelectionDisplay(witnessKeyID string) string {
	if witnessKeyID == "" {
		return "Choose an enrolled sentry"
	}
	for _, choice := range m.choicesForAllReferences() {
		if choice.WitnessKeyID == witnessKeyID {
			return fmt.Sprintf("%s  %s", choice.PrimaryAlias, apadminapp.CompactWitnessKeyID(witnessKeyID))
		}
	}
	return apadminapp.CompactWitnessKeyID(witnessKeyID)
}

func (m Model) choicesForAllReferences() []sentryChoice {
	seenTypes := make(map[string]bool)
	var choices []sentryChoice
	for _, reference := range m.sentry.references {
		if seenTypes[reference.KeyType] {
			continue
		}
		seenTypes[reference.KeyType] = true
		choices = append(choices, m.compatibleSentryChoices(reference.KeyType)...)
	}
	return choices
}

func (m Model) renderSentryPicker() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Choose Sentry"))
	body.WriteString("\n\n")
	body.WriteString(subtitleStyle.Render("Select the enrolled witness authority for this guarded account."))
	body.WriteString("\n\n")
	for index, choice := range m.sentry.choices {
		prefix := "  "
		if index == m.sentry.selected {
			prefix = "> "
		}
		row := fmt.Sprintf("%s%s  %s", prefix, choice.PrimaryAlias, apadminapp.CompactWitnessKeyID(choice.WitnessKeyID))
		if len(choice.Aliases) > 1 {
			row += fmt.Sprintf("  (%d aliases)", len(choice.Aliases))
		}
		if index == m.sentry.selected {
			body.WriteString(selectedStyle.Render(row))
		} else {
			body.WriteString(row)
		}
		body.WriteString("\n")
	}
	body.WriteString("\n")
	body.WriteString(helpStyle.Render("↑/↓ navigate  Enter select  Esc cancel"))
	body.WriteString("\n")
	return m.renderPopup(80, body.String())
}

func (m Model) renderSentryImportForm() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Enroll Sentry"))
	body.WriteString("\n\n")
	if m.sentry.importPaste {
		body.WriteString(subtitleStyle.Render("Paste the public JSON exported by the sentry node (up to 64 KiB)."))
	} else {
		body.WriteString(subtitleStyle.Render("Choose the public envelope exported by the sentry node."))
	}
	body.WriteString("\n\n")

	pathStyle := inputInactiveStyle
	nameStyle := inputInactiveStyle
	if m.sentry.importFocus == 0 {
		pathStyle = inputActiveStyle
	}
	if m.sentry.importFocus == 1 {
		nameStyle = inputActiveStyle
	}
	if m.sentry.importPaste {
		body.WriteString("Public enrollment JSON:\n")
		preview := "Paste JSON here"
		if m.sentry.importJSON != "" {
			preview = fmt.Sprintf("%d bytes captured; paste again to replace", len(m.sentry.importJSON))
		}
		body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(preview))
		body.WriteString("\n" + helpStyle.Render("Use your terminal paste shortcut. Backspace/Delete clears the JSON."))
	} else {
		body.WriteString("Public envelope path:\n")
		body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(m.sentry.importPath))
	}
	body.WriteString("\n\nSuggested name:\n")
	body.WriteString(nameStyle.Width(m.constrainParameterFieldWidth(40)).Render(m.sentry.importName))
	body.WriteString("\n\n")
	button := buttonInactiveStyle.Render("REVIEW ENROLLMENT")
	if m.sentry.importFocus == 2 {
		button = buttonActiveStyle.Render("REVIEW ENROLLMENT")
	}
	body.WriteString(button)
	body.WriteString("\n")
	if m.sentry.importError != "" {
		body.WriteString("\n")
		body.WriteString(errorStyle.Render(m.sentry.importError))
		body.WriteString("\n")
	}
	return m.renderPopup(80, body.String())
}

func (m Model) renderSentryImportReview() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Review Sentry Enrollment"))
	body.WriteString("\n\n")
	body.WriteString("Signer effect: enroll verifier as " + m.sentry.importName + "\n")
	body.WriteString("Key type: " + m.sentry.previewKeyType + "\n\n")
	body.WriteString("Witness Key ID (compare the complete value):\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.sentry.previewWitnessID), m.popupBodyWidth(90)))
	body.WriteString("\n\n")
	if m.sentry.previewEndpoint != nil {
		body.WriteString("Bundle contains endpoint metadata. Configure the transaction client separately in apshell.\n")
	}
	body.WriteString("\n")
	button := buttonActiveStyle.Render("ENROLL")
	body.WriteString(button)
	body.WriteString("\n")
	body.WriteString(warningStyle.Render("Compare the complete Witness Key ID before enrolling."))
	if m.sentry.importError != "" {
		body.WriteString("\n\n")
		body.WriteString(errorStyle.Render(m.sentry.importError))
	}
	body.WriteString("\n")
	return m.renderPopup(90, body.String())
}

func (m Model) renderSentryImporting() string {
	return m.renderPopup(60, titleStyle.Render("Enrolling Sentry")+"\n\n"+subtitleStyle.Render("Please wait...")+"\n")
}
