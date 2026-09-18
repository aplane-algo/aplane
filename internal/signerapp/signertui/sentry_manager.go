// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) sortedSentryReferences() []SentryReferenceInfo {
	references := append([]SentryReferenceInfo(nil), m.sentry.references...)
	sort.Slice(references, func(i, j int) bool {
		left := strings.ToLower(references[i].Name)
		right := strings.ToLower(references[j].Name)
		if left != right {
			return left < right
		}
		if references[i].ComponentKey != references[j].ComponentKey {
			return references[i].ComponentKey < references[j].ComponentKey
		}
		return references[i].KeyType < references[j].KeyType
	})
	return references
}

func (m Model) selectedSentryReference() (SentryReferenceInfo, bool) {
	references := m.sortedSentryReferences()
	if m.sentry.managerSelected < 0 || m.sentry.managerSelected >= len(references) {
		return SentryReferenceInfo{}, false
	}
	return references[m.sentry.managerSelected], true
}

func (m Model) openSentryReferenceManager() (tea.Model, tea.Cmd) {
	if m.isSentryNode() {
		m.lastError = "Public sentry references are managed on signer nodes"
		return m, nil
	}
	m.sentry.managerSelected = 0
	m.sentry.managerScroll = 0
	m.sentry.managerStatus = ""
	m.viewState = ViewSentryReferences
	return m, tea.Batch(m.sendListSentryReferencesCmd(), m.waitForMessageCmd())
}

func (m Model) beginManagerSentryImport() Model {
	m.clearSentryImportTransient()
	m.sentry.importPath = ""
	m.sentry.importName = ""
	m.sentry.importFocus = 0
	m.sentry.importError = ""
	m.sentry.paramName = ""
	m.sentry.returnView = ViewSentryReferences
	m.sentry.requiredKeyType = ""
	m.clearSentryImportEnvelope()
	m.viewState = ViewSentryImportForm
	return m
}

func (m Model) handleSentryReferencesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	references := m.sortedSentryReferences()
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewKeyList
		m.sentry.managerStatus = ""
		return m, nil
	case "i":
		return m.beginManagerSentryImport(), nil
	case "p":
		m = m.beginManagerSentryImport()
		m.sentry.importPaste = true
		return m, nil
	case "r":
		m.sentry.managerStatus = "Refreshing..."
		return m, tea.Batch(m.sendListSentryReferencesCmd(), m.waitForMessageCmd())
	case "up", "k":
		if m.sentry.managerSelected > 0 {
			m.sentry.managerSelected--
		}
	case "down", "j":
		if m.sentry.managerSelected+1 < len(references) {
			m.sentry.managerSelected++
		}
	case "enter", " ":
		if _, ok := m.selectedSentryReference(); ok {
			m.sentry.importError = ""
			m.viewState = ViewSentryReferenceDetails
		}
	}
	m.clampSentryManagerScroll(len(references))
	return m, nil
}

func (m *Model) clampSentryManagerScroll(count int) {
	if count == 0 {
		m.sentry.managerSelected = 0
		m.sentry.managerScroll = 0
		return
	}
	if m.sentry.managerSelected >= count {
		m.sentry.managerSelected = count - 1
	}
	if m.sentry.managerSelected < 0 {
		m.sentry.managerSelected = 0
	}
	visible := m.sentryManagerVisibleRows()
	if m.sentry.managerSelected < m.sentry.managerScroll {
		m.sentry.managerScroll = m.sentry.managerSelected
	}
	if m.sentry.managerSelected >= m.sentry.managerScroll+visible {
		m.sentry.managerScroll = m.sentry.managerSelected - visible + 1
	}
	maxScroll := count - visible
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.sentry.managerScroll > maxScroll {
		m.sentry.managerScroll = maxScroll
	}
}

func (m Model) sentryManagerVisibleRows() int {
	rows := m.windowBodyHeight() - 10
	if rows < 3 {
		return 3
	}
	return rows
}

func (m Model) handleSentryReferenceDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewSentryReferences
	case "g":
		return m.beginSelectedSentryGeneration()
	case "d":
		if _, ok := m.selectedSentryReference(); ok {
			m.sentry.removeFocus = 0
			m.sentry.importError = ""
			m.viewState = ViewSentryRemoveConfirm
		}
	}
	return m, nil
}

func (m Model) compatibleSentryGenerateTypeIndices(componentKeyType string) []int {
	var indices []int
	for index, info := range getServerKeyTypes() {
		if info.SentryComponentKeyType == componentKeyType {
			indices = append(indices, index)
		}
	}
	return indices
}

func (m Model) beginSelectedSentryGeneration() (tea.Model, tea.Cmd) {
	reference, ok := m.selectedSentryReference()
	if !ok {
		m.sentry.managerStatus = "Sentry reference is no longer available"
		m.viewState = ViewSentryReferences
		return m, nil
	}
	indices := m.compatibleSentryGenerateTypeIndices(reference.KeyType)
	switch len(indices) {
	case 0:
		m.sentry.importError = "No enabled account key type accepts this witness key type"
		return m, nil
	case 1:
		return m.beginGenerateWithSentryReference(indices[0], reference)
	default:
		m.sentry.generateTypeIndices = indices
		m.sentry.generateTypeSelected = 0
		m.sentry.importError = ""
		m.viewState = ViewSentryGenerateType
		return m, nil
	}
}

func (m Model) beginGenerateWithSentryReference(keyTypeIndex int, reference SentryReferenceInfo) (tea.Model, tea.Cmd) {
	keyType := getKeyTypeByIndex(keyTypeIndex)
	if keyType == "" {
		m.sentry.importError = "Compatible account key type is no longer available"
		m.viewState = ViewSentryReferenceDetails
		return m, nil
	}
	info, ok := findServerKeyType(keyType)
	if !ok || info.SentryComponentKeyType != reference.KeyType {
		m.sentry.importError = "Compatible account key type is no longer available"
		m.viewState = ViewSentryReferenceDetails
		return m, nil
	}
	m.forms.generateKeyType = keyTypeIndex
	m.forms.generateFocus = 0
	m.forms.generateError = ""
	m = m.initGenericLSigParamsForKeyType(keyType)
	paramIndex := -1
	for index, name := range m.forms.genericLSigParamOrder {
		if name == "sentry" {
			paramIndex = index
			break
		}
	}
	if paramIndex < 0 {
		m.sentry.importError = "Compatible account key type does not expose a sentry selector"
		m.viewState = ViewSentryReferenceDetails
		return m, nil
	}
	m.forms.genericLSigParams["sentry"] = reference.ComponentKey
	m.forms.generateFocus = paramIndex
	m.sentry.generateFromManager = true
	m.sentry.importError = ""
	m.viewState = ViewGenerateParams
	return m, nil
}

func (m Model) handleSentryGenerateTypeKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.sentry.generateTypeIndices = nil
		m.sentry.generateTypeSelected = 0
		m.viewState = ViewSentryReferenceDetails
		return m, nil
	case "up", "k":
		if m.sentry.generateTypeSelected > 0 {
			m.sentry.generateTypeSelected--
		}
	case "down", "j":
		if m.sentry.generateTypeSelected+1 < len(m.sentry.generateTypeIndices) {
			m.sentry.generateTypeSelected++
		}
	case "enter", " ":
		reference, ok := m.selectedSentryReference()
		if !ok || m.sentry.generateTypeSelected < 0 || m.sentry.generateTypeSelected >= len(m.sentry.generateTypeIndices) {
			m.sentry.importError = "Sentry reference or compatible account key type is no longer available"
			m.viewState = ViewSentryReferenceDetails
			return m, nil
		}
		return m.beginGenerateWithSentryReference(m.sentry.generateTypeIndices[m.sentry.generateTypeSelected], reference)
	}
	return m, nil
}

func (m Model) handleSentryRemoveConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	reference, ok := m.selectedSentryReference()
	if !ok {
		m.viewState = ViewSentryReferences
		return m, nil
	}
	switch msg.String() {
	case "left", "right", "tab", "shift+tab":
		m.sentry.removeFocus = 1 - m.sentry.removeFocus
	case "esc", "n":
		m.viewState = ViewSentryReferenceDetails
		m.sentry.removeFocus = 0
	case "y":
		m.sentry.removeFocus = 1
		fallthrough
	case "enter", " ":
		if m.sentry.removeFocus == 0 {
			m.viewState = ViewSentryReferenceDetails
			return m, nil
		}
		m.viewState = ViewSentryRemoving
		return m, tea.Batch(m.sendRemoveSentryReferenceCmd(reference.Name), m.waitForMessageCmd())
	}
	return m, nil
}

func (m Model) renderSentryReferences() string {
	references := m.sortedSentryReferences()
	var body strings.Builder
	body.WriteString(titleStyle.Render("Sentry References"))
	body.WriteString("\n")
	body.WriteString(subtitleStyle.Render("Public witness authorities enrolled for guarded-account generation."))
	body.WriteString("\n\n")
	if len(references) == 0 {
		body.WriteString("No sentry references enrolled. Press i to import a public envelope file or p to paste JSON.\n")
	} else {
		start := m.sentry.managerScroll
		end := start + m.sentryManagerVisibleRows()
		if end > len(references) {
			end = len(references)
		}
		body.WriteString(scrollMoreAboveLine(start))
		body.WriteString("\n")
		for index := start; index < end; index++ {
			reference := references[index]
			prefix := "  "
			if index == m.sentry.managerSelected {
				prefix = "> "
			}
			row := fmt.Sprintf("%s%s  %s  %s",
				prefix,
				reference.Name,
				apadminapp.CompactWitnessKeyID(reference.ComponentKey),
				displayKeyType(reference.KeyType),
			)
			if index == m.sentry.managerSelected {
				body.WriteString(selectedStyle.Render(row))
			} else {
				body.WriteString(row)
			}
			body.WriteString("\n")
		}
		body.WriteString(scrollMoreBelowLine(len(references) - end))
		body.WriteString("\n")
	}
	if m.sentry.managerStatus != "" {
		body.WriteString("\n")
		body.WriteString(subtitleStyle.Render(m.sentry.managerStatus))
		body.WriteString("\n")
	}
	return body.String()
}

func (m Model) renderSentryReferenceDetails() string {
	reference, ok := m.selectedSentryReference()
	if !ok {
		return m.renderPopup(70, "Sentry reference is no longer available")
	}
	aliases := make([]string, 0)
	for _, candidate := range m.sortedSentryReferences() {
		if candidate.ComponentKey == reference.ComponentKey && candidate.KeyType == reference.KeyType {
			aliases = append(aliases, candidate.Name)
		}
	}
	var body strings.Builder
	body.WriteString(titleStyle.Render("Sentry Reference Details"))
	body.WriteString("\n\n")
	body.WriteString("Name:     " + reference.Name + "\n")
	body.WriteString("Key type: " + reference.KeyType + "\n")
	if len(aliases) > 1 {
		body.WriteString("Aliases:  " + strings.Join(aliases, ", ") + "\n")
	}
	body.WriteString("\nWitness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(reference.ComponentKey), m.popupBodyWidth(90)))
	body.WriteString("\n")
	if reference.PublicKeySHA256 != "" {
		body.WriteString("\nPublic key SHA-256: " + reference.PublicKeySHA256 + "\n")
	}
	if reference.ImportedAt != "" {
		body.WriteString("Imported: " + reference.ImportedAt + "\n")
	}
	if reference.MigrationOrigin != "" {
		body.WriteString("Migration origin: " + reference.MigrationOrigin + "\n")
	}
	if m.sentry.importError != "" {
		body.WriteString("\n" + errorStyle.Render(m.sentry.importError) + "\n")
	}
	if m.sentry.managerStatus != "" {
		body.WriteString("\n" + subtitleStyle.Render(m.sentry.managerStatus) + "\n")
	}
	return m.renderPopup(90, body.String())
}

func (m Model) renderSentryGenerateType() string {
	reference, ok := m.selectedSentryReference()
	if !ok {
		return m.renderPopup(70, "Sentry reference is no longer available")
	}
	keyTypes := getServerKeyTypes()
	var body strings.Builder
	body.WriteString(titleStyle.Render("Generate Guarded Account"))
	body.WriteString("\n\n")
	body.WriteString("Sentry: " + reference.Name + "  " + apadminapp.CompactWitnessKeyID(reference.ComponentKey) + "\n\n")
	body.WriteString("Choose a compatible account key type:\n\n")
	for row, index := range m.sentry.generateTypeIndices {
		if index < 0 || index >= len(keyTypes) {
			continue
		}
		label := displayKeyType(keyTypes[index].KeyType)
		prefix := "  "
		if row == m.sentry.generateTypeSelected {
			prefix = "> "
			body.WriteString(selectedStyle.Render(prefix + label))
		} else {
			body.WriteString(prefix + label)
		}
		body.WriteString("\n")
	}
	return m.renderPopup(80, body.String())
}

func (m Model) renderSentryRemoveConfirm() string {
	reference, ok := m.selectedSentryReference()
	if !ok {
		return m.renderPopup(70, "Sentry reference is no longer available")
	}
	var body strings.Builder
	body.WriteString(warningStyle.Render("REMOVE SENTRY REFERENCE"))
	body.WriteString("\n\n")
	body.WriteString("Remove alias " + reference.Name + " from guarded-account generation?\n\n")
	body.WriteString("Witness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(reference.ComponentKey), m.popupBodyWidth(80)))
	body.WriteString("\n\n")
	cancel := buttonInactiveStyle.Render("CANCEL")
	remove := buttonInactiveStyle.Render("REMOVE")
	if m.sentry.removeFocus == 0 {
		cancel = buttonActiveStyle.Render("CANCEL")
	} else {
		remove = buttonActiveStyle.Render("REMOVE")
	}
	body.WriteString(cancel + "  " + remove)
	body.WriteString("\n")
	if m.sentry.importError != "" {
		body.WriteString("\n" + errorStyle.Render(m.sentry.importError) + "\n")
	}
	return m.renderPopup(80, body.String())
}

func (m Model) renderSentryRemoving() string {
	return m.renderPopup(60, titleStyle.Render("Removing Sentry Reference")+"\n\n"+subtitleStyle.Render("Please wait...")+"\n")
}
