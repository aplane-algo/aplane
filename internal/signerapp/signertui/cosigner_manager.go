// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) sortedCosignerReferences() []CosignerReferenceInfo {
	references := append([]CosignerReferenceInfo(nil), m.cosigner.references...)
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

func (m Model) selectedCosignerReference() (CosignerReferenceInfo, bool) {
	references := m.sortedCosignerReferences()
	if m.cosigner.managerSelected < 0 || m.cosigner.managerSelected >= len(references) {
		return CosignerReferenceInfo{}, false
	}
	return references[m.cosigner.managerSelected], true
}

func (m Model) openCosignerReferenceManager() (tea.Model, tea.Cmd) {
	// Cosigner nodes export public references; they never import them, so
	// the manager is not offered there and the key binding is inert.
	if m.isCosignerNode() {
		return m, nil
	}
	m.cosigner.managerSelected = 0
	m.cosigner.managerScroll = 0
	m.cosigner.managerStatus = ""
	m.viewState = ViewCosignerReferences
	return m, tea.Batch(m.sendListCosignerReferencesCmd(), m.waitForMessageCmd())
}

func (m Model) beginManagerCosignerImport() Model {
	m.clearCosignerImportTransient()
	m.cosigner.importPath = ""
	m.cosigner.importName = ""
	m.cosigner.importFocus = 0
	m.cosigner.importError = ""
	m.cosigner.paramName = ""
	m.cosigner.returnView = ViewCosignerReferences
	m.cosigner.requiredKeyType = ""
	m.clearCosignerImportEnvelope()
	m.viewState = ViewCosignerImportForm
	return m
}

func (m Model) handleCosignerReferencesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	references := m.sortedCosignerReferences()
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewKeyList
		m.cosigner.managerStatus = ""
		return m, nil
	case "i":
		return m.beginManagerCosignerImport(), nil
	case "p":
		m = m.beginManagerCosignerImport()
		m.cosigner.importPaste = true
		return m, nil
	case "r":
		m.cosigner.managerStatus = "Refreshing..."
		return m, tea.Batch(m.sendListCosignerReferencesCmd(), m.waitForMessageCmd())
	case "up", "k":
		if m.cosigner.managerSelected > 0 {
			m.cosigner.managerSelected--
		}
	case "down", "j":
		if m.cosigner.managerSelected+1 < len(references) {
			m.cosigner.managerSelected++
		}
	case "enter", " ":
		if _, ok := m.selectedCosignerReference(); ok {
			m.cosigner.importError = ""
			m.viewState = ViewCosignerReferenceDetails
		}
	}
	m.clampCosignerManagerScroll(len(references))
	return m, nil
}

func (m *Model) clampCosignerManagerScroll(count int) {
	if count == 0 {
		m.cosigner.managerSelected = 0
		m.cosigner.managerScroll = 0
		return
	}
	if m.cosigner.managerSelected >= count {
		m.cosigner.managerSelected = count - 1
	}
	if m.cosigner.managerSelected < 0 {
		m.cosigner.managerSelected = 0
	}
	visible := m.cosignerManagerVisibleRows()
	if m.cosigner.managerSelected < m.cosigner.managerScroll {
		m.cosigner.managerScroll = m.cosigner.managerSelected
	}
	if m.cosigner.managerSelected >= m.cosigner.managerScroll+visible {
		m.cosigner.managerScroll = m.cosigner.managerSelected - visible + 1
	}
	maxScroll := count - visible
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.cosigner.managerScroll > maxScroll {
		m.cosigner.managerScroll = maxScroll
	}
}

func (m Model) cosignerManagerVisibleRows() int {
	rows := m.windowBodyHeight() - 10
	if rows < 3 {
		return 3
	}
	return rows
}

func (m Model) handleCosignerReferenceDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewCosignerReferences
	case "g":
		return m.beginSelectedCosignerGeneration()
	case "d":
		if _, ok := m.selectedCosignerReference(); ok {
			m.cosigner.removeFocus = 0
			m.cosigner.importError = ""
			m.viewState = ViewCosignerRemoveConfirm
		}
	}
	return m, nil
}

func (m Model) compatibleCosignerGenerateTypeIndices(componentKeyType string) []int {
	var indices []int
	for index, info := range getServerKeyTypes() {
		if info.CosignerComponentKeyType == componentKeyType {
			indices = append(indices, index)
		}
	}
	return indices
}

func (m Model) beginSelectedCosignerGeneration() (tea.Model, tea.Cmd) {
	reference, ok := m.selectedCosignerReference()
	if !ok {
		m.cosigner.managerStatus = "Cosigner reference is no longer available"
		m.viewState = ViewCosignerReferences
		return m, nil
	}
	indices := m.compatibleCosignerGenerateTypeIndices(reference.KeyType)
	switch len(indices) {
	case 0:
		m.cosigner.importError = "No enabled account key type accepts this witness key type"
		return m, nil
	case 1:
		return m.beginGenerateWithCosignerReference(indices[0], reference)
	default:
		m.cosigner.generateTypeIndices = indices
		m.cosigner.generateTypeSelected = 0
		m.cosigner.importError = ""
		m.viewState = ViewCosignerGenerateType
		return m, nil
	}
}

func (m Model) beginGenerateWithCosignerReference(keyTypeIndex int, reference CosignerReferenceInfo) (tea.Model, tea.Cmd) {
	keyType := getKeyTypeByIndex(keyTypeIndex)
	if keyType == "" {
		m.cosigner.importError = "Compatible account key type is no longer available"
		m.viewState = ViewCosignerReferenceDetails
		return m, nil
	}
	info, ok := findServerKeyType(keyType)
	if !ok || info.CosignerComponentKeyType != reference.KeyType {
		m.cosigner.importError = "Compatible account key type is no longer available"
		m.viewState = ViewCosignerReferenceDetails
		return m, nil
	}
	m.forms.generateKeyType = keyTypeIndex
	m.forms.generateFocus = 0
	m.forms.generateError = ""
	m = m.initGenericLSigParamsForKeyType(keyType)
	paramIndex := -1
	for index, name := range m.forms.genericLSigParamOrder {
		if name == cosignerrefs.ParamCosignerName {
			paramIndex = index
			break
		}
	}
	if paramIndex < 0 {
		m.cosigner.importError = "Compatible account key type does not expose a cosigner selector"
		m.viewState = ViewCosignerReferenceDetails
		return m, nil
	}
	m.forms.genericLSigParams[cosignerrefs.ParamCosignerName] = reference.ComponentKey
	m.forms.generateFocus = paramIndex
	m.cosigner.generateFromManager = true
	m.cosigner.importError = ""
	m.viewState = ViewGenerateParams
	return m, nil
}

func (m Model) handleCosignerGenerateTypeKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.cosigner.generateTypeIndices = nil
		m.cosigner.generateTypeSelected = 0
		m.viewState = ViewCosignerReferenceDetails
		return m, nil
	case "up", "k":
		if m.cosigner.generateTypeSelected > 0 {
			m.cosigner.generateTypeSelected--
		}
	case "down", "j":
		if m.cosigner.generateTypeSelected+1 < len(m.cosigner.generateTypeIndices) {
			m.cosigner.generateTypeSelected++
		}
	case "enter", " ":
		reference, ok := m.selectedCosignerReference()
		if !ok || m.cosigner.generateTypeSelected < 0 || m.cosigner.generateTypeSelected >= len(m.cosigner.generateTypeIndices) {
			m.cosigner.importError = "Cosigner reference or compatible account key type is no longer available"
			m.viewState = ViewCosignerReferenceDetails
			return m, nil
		}
		return m.beginGenerateWithCosignerReference(m.cosigner.generateTypeIndices[m.cosigner.generateTypeSelected], reference)
	}
	return m, nil
}

func (m Model) handleCosignerRemoveConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	reference, ok := m.selectedCosignerReference()
	if !ok {
		m.viewState = ViewCosignerReferences
		return m, nil
	}
	switch msg.String() {
	case "left", "right", "tab", "shift+tab":
		m.cosigner.removeFocus = 1 - m.cosigner.removeFocus
	case "esc", "n":
		m.viewState = ViewCosignerReferenceDetails
		m.cosigner.removeFocus = 0
	case "y":
		m.cosigner.removeFocus = 1
		fallthrough
	case "enter", " ":
		if m.cosigner.removeFocus == 0 {
			m.viewState = ViewCosignerReferenceDetails
			return m, nil
		}
		m.viewState = ViewCosignerRemoving
		return m, tea.Batch(m.sendRemoveCosignerReferenceCmd(reference.Name), m.waitForMessageCmd())
	}
	return m, nil
}

func (m Model) renderCosignerReferences() string {
	references := m.sortedCosignerReferences()
	var body strings.Builder
	body.WriteString(titleStyle.Render("Cosigner References"))
	body.WriteString("\n")
	body.WriteString(subtitleStyle.Render("Public witness authorities enrolled for guarded-account generation."))
	body.WriteString("\n\n")
	if len(references) == 0 {
		body.WriteString("No cosigner references enrolled. Press i to import a public envelope file or p to paste JSON.\n")
	} else {
		start := m.cosigner.managerScroll
		end := start + m.cosignerManagerVisibleRows()
		if end > len(references) {
			end = len(references)
		}
		body.WriteString(scrollMoreAboveLine(start))
		body.WriteString("\n")
		for index := start; index < end; index++ {
			reference := references[index]
			prefix := "  "
			if index == m.cosigner.managerSelected {
				prefix = "> "
			}
			row := fmt.Sprintf("%s%s  %s  %s",
				prefix,
				reference.Name,
				apadminapp.CompactWitnessKeyID(reference.ComponentKey),
				displayKeyType(reference.KeyType),
			)
			if index == m.cosigner.managerSelected {
				body.WriteString(selectedStyle.Render(row))
			} else {
				body.WriteString(row)
			}
			body.WriteString("\n")
		}
		body.WriteString(scrollMoreBelowLine(len(references) - end))
		body.WriteString("\n")
	}
	if m.cosigner.managerStatus != "" {
		body.WriteString("\n")
		body.WriteString(subtitleStyle.Render(m.cosigner.managerStatus))
		body.WriteString("\n")
	}
	return body.String()
}

func (m Model) renderCosignerReferenceDetails() string {
	reference, ok := m.selectedCosignerReference()
	if !ok {
		return m.renderPopup(70, "Cosigner reference is no longer available")
	}
	aliases := make([]string, 0)
	for _, candidate := range m.sortedCosignerReferences() {
		if candidate.ComponentKey == reference.ComponentKey && candidate.KeyType == reference.KeyType {
			aliases = append(aliases, candidate.Name)
		}
	}
	var body strings.Builder
	body.WriteString(titleStyle.Render("Cosigner Reference Details"))
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
	if m.cosigner.importError != "" {
		body.WriteString("\n" + errorStyle.Render(m.cosigner.importError) + "\n")
	}
	if m.cosigner.managerStatus != "" {
		body.WriteString("\n" + subtitleStyle.Render(m.cosigner.managerStatus) + "\n")
	}
	return m.renderPopup(90, body.String())
}

func (m Model) renderCosignerGenerateType() string {
	reference, ok := m.selectedCosignerReference()
	if !ok {
		return m.renderPopup(70, "Cosigner reference is no longer available")
	}
	keyTypes := getServerKeyTypes()
	var body strings.Builder
	body.WriteString(titleStyle.Render("Generate Guarded Account"))
	body.WriteString("\n\n")
	body.WriteString("Cosigner: " + reference.Name + "  " + apadminapp.CompactWitnessKeyID(reference.ComponentKey) + "\n\n")
	body.WriteString("Choose a compatible account key type:\n\n")
	for row, index := range m.cosigner.generateTypeIndices {
		if index < 0 || index >= len(keyTypes) {
			continue
		}
		label := displayKeyType(keyTypes[index].KeyType)
		prefix := "  "
		if row == m.cosigner.generateTypeSelected {
			prefix = "> "
			body.WriteString(selectedStyle.Render(prefix + label))
		} else {
			body.WriteString(prefix + label)
		}
		body.WriteString("\n")
	}
	return m.renderPopup(80, body.String())
}

func (m Model) renderCosignerRemoveConfirm() string {
	reference, ok := m.selectedCosignerReference()
	if !ok {
		return m.renderPopup(70, "Cosigner reference is no longer available")
	}
	var body strings.Builder
	body.WriteString(warningStyle.Render("REMOVE COSIGNER REFERENCE"))
	body.WriteString("\n\n")
	body.WriteString("Remove alias " + reference.Name + " from guarded-account generation?\n\n")
	body.WriteString("Witness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(reference.ComponentKey), m.popupBodyWidth(80)))
	body.WriteString("\n\n")
	cancel := buttonInactiveStyle.Render("CANCEL")
	remove := buttonInactiveStyle.Render("REMOVE")
	if m.cosigner.removeFocus == 0 {
		cancel = buttonActiveStyle.Render("CANCEL")
	} else {
		remove = buttonActiveStyle.Render("REMOVE")
	}
	body.WriteString(cancel + "  " + remove)
	body.WriteString("\n")
	if m.cosigner.importError != "" {
		body.WriteString("\n" + errorStyle.Render(m.cosigner.importError) + "\n")
	}
	return m.renderPopup(80, body.String())
}

func (m Model) renderCosignerRemoving() string {
	return m.renderPopup(60, titleStyle.Render("Removing Cosigner Reference")+"\n\n"+subtitleStyle.Render("Please wait...")+"\n")
}
