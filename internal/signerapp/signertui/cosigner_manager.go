// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) sortedCosignerReferences() []CosignerReferenceInfo {
	references := append([]CosignerReferenceInfo(nil), m.cosigner.references...)
	sort.Slice(references, func(i, j int) bool {
		if references[i].Name != references[j].Name {
			return references[i].Name < references[j].Name
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

// cosignerManagerRows is how many rows the manager lists: the references,
// then the reference files that are not valid references.
func (m Model) cosignerManagerRows() int {
	return len(m.cosigner.references) + len(m.cosigner.invalid)
}

// selectedInvalidCosignerReference returns the selected row when it is a
// reference file that is not a valid reference.
func (m Model) selectedInvalidCosignerReference() (InvalidCosignerReferenceInfo, bool) {
	index := m.cosigner.managerSelected - len(m.cosigner.references)
	if index < 0 || index >= len(m.cosigner.invalid) {
		return InvalidCosignerReferenceInfo{}, false
	}
	return m.cosigner.invalid[index], true
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
	m.cosigner.deleteHint = ""
	m.viewState = ViewCosignerReferences
	return m, m.sendListCosignerReferencesCmd()
}

func (m Model) beginManagerCosignerImport() Model {
	m.clearCosignerImportTransient()
	m.cosigner.importFocus = 0
	m.cosigner.paramName = ""
	m.cosigner.returnView = ViewCosignerReferences
	m.viewState = ViewCosignerImportForm
	return m
}

func (m Model) handleCosignerReferencesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	selected := m.cosigner.managerSelected
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewKeyList
		m.cosigner.managerStatus = ""
		m.cosigner.deleteHint = ""
		return m, nil
	case "i":
		return m.beginManagerCosignerImport(), nil
	case "p":
		m = m.beginManagerCosignerImport()
		m.cosigner.importPaste = true
		return m, nil
	case "r":
		m.cosigner.managerStatus = "Refreshing..."
		return m, m.sendListCosignerReferencesCmd()
	case "up", "k":
		if m.cosigner.managerSelected > 0 {
			m.cosigner.managerSelected--
		}
	case "down", "j":
		if m.cosigner.managerSelected+1 < m.cosignerManagerRows() {
			m.cosigner.managerSelected++
		}
	case "enter", " ":
		if reference, ok := m.selectedCosignerReference(); ok {
			m.cosigner.detailsName = reference.Name
			m.cosigner.importError = ""
			m.viewState = ViewCosignerReferenceDetails
		} else if bad, ok := m.selectedInvalidCosignerReference(); ok {
			m = m.beginInvalidCosignerReferenceClear(bad)
		}
	}
	// The hint is about the row it was given for.
	if m.cosigner.managerSelected != selected {
		m.cosigner.deleteHint = ""
	}
	m.clampCosignerManagerScroll(m.cosignerManagerRows())
	return m, nil
}

// beginInvalidCosignerReferenceClear confirms the removal of a file that
// remove clears, as for a reference; of any other it says to delete it.
func (m Model) beginInvalidCosignerReferenceClear(bad InvalidCosignerReferenceInfo) Model {
	if !bad.Removable {
		m.cosigner.deleteHint = bad.Path
		return m
	}
	return m.beginCosignerRemoval(bad.Name, true)
}

// beginCosignerRemoval opens the remove confirmation, on Cancel, for the
// reference or reference file called name.
func (m Model) beginCosignerRemoval(name string, invalid bool) Model {
	m.cosigner.removeName = name
	m.cosigner.removeInvalid = invalid
	m.cosigner.removeFocus = 0
	m.cosigner.importError = ""
	m.viewState = ViewCosignerRemoveConfirm
	return m
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
	// The title block and the two scroll lines are around the list, and 5
	// more lines are kept for a list error and the status. A longer one takes
	// rows from the list, so the window does not cut it off, until the list
	// is down to its last 3 rows.
	extra := renderedBlockHeight(m.cosignerListErrorBlock())
	if status := m.cosignerManagerStatusBlock(); status != "" {
		extra += 1 + renderedBlockHeight(status)
	}
	rows := m.windowBodyHeight() - strings.Count(cosignerManagerTitle(), "\n") - 2 - max(5, extra)
	if len(m.cosigner.invalid) > 0 {
		rows -= 2 // the invalid-file note and the blank line above it
	}
	if rows < 3 {
		return 3
	}
	return rows
}

// cosignerManagerTitle is the block above the list: the title, its margin
// and a blank line.
func cosignerManagerTitle() string {
	return titleStyle.Render("Cosigner References") + "\n\n"
}

// cosignerListErrorBlock is what the manager shows above the list when the
// last list failed.
func (m Model) cosignerListErrorBlock() string {
	if m.cosigner.listErr == "" {
		return ""
	}
	block := errorStyle.Render(wrapPlainText("Cosigner references could not be listed: "+terminalSafe(m.cosigner.listErr), m.tableWidth())) + "\n"
	if m.cosignerManagerRows() > 0 {
		block += subtitleStyle.Render("Showing the last list read.") + "\n"
	}
	return block
}

// cosignerManagerStatusBlock is what the manager shows below the list: its
// status, then the hint for a reference file remove does not reach, with
// the file's path broken across lines so all of it stays on screen.
func (m Model) cosignerManagerStatusBlock() string {
	var lines []string
	if m.cosigner.managerStatus != "" {
		lines = append(lines, subtitleStyle.Render(wrapPlainText(m.cosigner.managerStatus, m.tableWidth())))
	}
	if m.cosigner.deleteHint != "" {
		path := terminalSafe(m.cosigner.deleteHint)
		lines = append(lines, subtitleStyle.Render(
			wrapPlainText("Remove does not reach this file; delete it to clear it:", m.tableWidth())+"\n"+
				wrapPath(path, m.tableWidth())))
	}
	return strings.Join(lines, "\n")
}

// wrapPath breaks path into lines of at most width runes, after a "/" where
// it can and inside a name wider than a line.
func wrapPath(path string, width int) string {
	if width <= 0 {
		return path
	}
	var lines []string
	line := ""
	for _, part := range strings.SplitAfter(path, "/") {
		for utf8.RuneCountInString(part) > width {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
			runes := []rune(part)
			lines = append(lines, string(runes[:width]))
			part = string(runes[width:])
		}
		if utf8.RuneCountInString(line)+utf8.RuneCountInString(part) > width {
			lines = append(lines, line)
			line = ""
		}
		line += part
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (m Model) handleCosignerReferenceDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewCosignerReferences
	case "g":
		return m.beginDetailsCosignerGeneration()
	case "d":
		if reference, ok := m.detailsCosignerReference(); ok {
			m = m.beginCosignerRemoval(reference.Name, false)
		}
	}
	return m, nil
}

// detailsCosignerReference finds the reference the details screen shows in
// the list as it now stands; ok is false once it is not listed.
func (m Model) detailsCosignerReference() (CosignerReferenceInfo, bool) {
	for _, reference := range m.cosigner.references {
		if reference.Name == m.cosigner.detailsName {
			return reference, true
		}
	}
	return CosignerReferenceInfo{}, false
}

func (m Model) compatibleCosignerGenerateTypeIndices(componentKeyType string) []int {
	var indices []int
	for index, info := range getServerKeyTypes() {
		if slices.Contains(info.CosignerComponentKeyTypes, componentKeyType) {
			indices = append(indices, index)
		}
	}
	return indices
}

func (m Model) beginDetailsCosignerGeneration() (tea.Model, tea.Cmd) {
	reference, ok := m.detailsCosignerReference()
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
	if !ok || !slices.Contains(info.CosignerComponentKeyTypes, reference.KeyType) {
		m.cosigner.importError = "Compatible account key type is no longer available"
		m.viewState = ViewCosignerReferenceDetails
		return m, nil
	}
	m = m.endBoundaryFlow()
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
		reference, ok := m.detailsCosignerReference()
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
	// A cancel returns to a reference's details, or to the list for a
	// reference file, which has no details.
	back := ViewCosignerReferenceDetails
	_, listed := m.cosignerRemovalReference()
	if m.cosigner.removeInvalid {
		back = ViewCosignerReferences
		_, listed = m.cosignerRemovalFile()
	}
	if !listed {
		m.viewState = ViewCosignerReferences
		return m, nil
	}
	switch msg.String() {
	case "left", "right", "tab", "shift+tab":
		m.cosigner.removeFocus = 1 - m.cosigner.removeFocus
	case "esc", "n":
		m.viewState = back
		m.cosigner.removeFocus = 0
	case "y":
		m.cosigner.removeFocus = 1
		fallthrough
	case "enter", " ":
		if m.cosigner.removeFocus == 0 {
			m.viewState = back
			return m, nil
		}
		id := m.beginOperation(ViewCosignerRemoving)
		return m, m.sendRemoveCosignerReferenceCmd(m.cosigner.removeName, id)
	}
	return m, nil
}

// cosignerRemovalReference finds the reference the remove confirmation
// removes in the list as it now stands; ok is false once it is not listed.
func (m Model) cosignerRemovalReference() (CosignerReferenceInfo, bool) {
	if m.cosigner.removeInvalid {
		return CosignerReferenceInfo{}, false
	}
	for _, reference := range m.cosigner.references {
		if reference.Name == m.cosigner.removeName {
			return reference, true
		}
	}
	return CosignerReferenceInfo{}, false
}

// cosignerRemovalFile finds the reference file the remove confirmation
// removes in the list as it now stands; ok is false once it is not listed as
// one remove clears.
func (m Model) cosignerRemovalFile() (InvalidCosignerReferenceInfo, bool) {
	if !m.cosigner.removeInvalid {
		return InvalidCosignerReferenceInfo{}, false
	}
	for _, bad := range m.cosigner.invalid {
		if bad.Name == m.cosigner.removeName && bad.Removable {
			return bad, true
		}
	}
	return InvalidCosignerReferenceInfo{}, false
}

func (m Model) renderCosignerReferences() string {
	references := m.sortedCosignerReferences()
	rows := m.cosignerManagerRows()
	// A list error or status that arrived after the last clamp can take
	// rows from the list; the selected row stays on screen.
	m.clampCosignerManagerScroll(rows)
	var body strings.Builder
	body.WriteString(cosignerManagerTitle())
	// A failed list says so: it is not an empty one.
	body.WriteString(m.cosignerListErrorBlock())
	if rows == 0 && m.cosigner.listErr != "" {
		body.WriteString(wrapPlainText("r lists them again.", m.tableWidth()) + "\n")
	} else if rows == 0 {
		body.WriteString(wrapPlainText("No cosigner references enrolled. Press i to import a public envelope file or p to paste JSON.", m.tableWidth()) + "\n")
	} else {
		nameWidth, idWidth := m.cosignerReferenceColumns(references)
		start := m.cosigner.managerScroll
		end := min(start+m.cosignerManagerVisibleRows(), rows)
		body.WriteString(scrollMoreAboveLine(start))
		body.WriteString("\n")
		for index := start; index < end; index++ {
			prefix := "  "
			if index == m.cosigner.managerSelected {
				prefix = "> "
			}
			var row string
			if index < len(references) {
				reference := references[index]
				row = fmt.Sprintf("%s%-*s  %-*s  %s",
					prefix,
					nameWidth, ellipsizeMiddle(reference.Name, nameWidth),
					idWidth, apadminapp.CompactWitnessKeyID(reference.ComponentKey),
					displayKeyType(reference.KeyType),
				)
			} else {
				bad := m.cosigner.invalid[index-len(references)]
				row = ellipsize(terminalSafe(prefix+filepath.Base(bad.Path)+": "+bad.Reason), m.tableWidth())
			}
			switch {
			case index == m.cosigner.managerSelected:
				body.WriteString(selectedStyle.Render(row))
			case index >= len(references):
				body.WriteString(errorStyle.Render(row))
			default:
				body.WriteString(row)
			}
			body.WriteString("\n")
		}
		body.WriteString(scrollMoreBelowLine(rows - end))
		body.WriteString("\n")
	}
	if count := len(m.cosigner.invalid); count > 0 {
		body.WriteString("\n")
		note := fmt.Sprintf("%d reference file(s) are not valid references; select one to clear it.", count)
		body.WriteString(errorStyle.Render(ellipsize(note, m.tableWidth())) + "\n")
	}
	if status := m.cosignerManagerStatusBlock(); status != "" {
		body.WriteString("\n" + status + "\n")
	}
	return body.String()
}

// cosignerReferenceColumns sizes the list from every reference, not just the
// visible ones, so columns hold still while scrolling. Only a name gives way
// when the window is tight; the details screen shows it in full.
func (m Model) cosignerReferenceColumns(references []CosignerReferenceInfo) (name, id int) {
	const cursorAndGaps, nameMinWidth = 2 + 2 + 2, 8
	keyType := 0
	for _, reference := range references {
		name = max(name, utf8.RuneCountInString(reference.Name))
		id = max(id, len(apadminapp.CompactWitnessKeyID(reference.ComponentKey)))
		keyType = max(keyType, len(displayKeyType(reference.KeyType)))
	}
	return min(name, max(m.tableWidth()-cursorAndGaps-id-keyType, nameMinWidth)), id
}

func (m Model) renderCosignerReferenceDetails() string {
	reference, ok := m.detailsCosignerReference()
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
	// The details show the public key's digest, not the key itself.
	if publicKey, err := hex.DecodeString(reference.PublicKeyHex); err == nil && len(publicKey) > 0 {
		digest := sha256.Sum256(publicKey)
		body.WriteString("\nPublic key SHA-256: " + hex.EncodeToString(digest[:]) + "\n")
	}
	if reference.ImportedAt != "" {
		body.WriteString("Imported: " + reference.ImportedAt + "\n")
	}
	if m.cosigner.importError != "" {
		body.WriteString("\n" + errorStyle.Render(terminalSafeLines(m.cosigner.importError)) + "\n")
	}
	if m.cosigner.managerStatus != "" {
		body.WriteString("\n" + subtitleStyle.Render(m.cosigner.managerStatus) + "\n")
	}
	return m.renderPopup(90, body.String())
}

func (m Model) renderCosignerGenerateType() string {
	reference, ok := m.detailsCosignerReference()
	if !ok {
		return m.renderPopup(70, "Cosigner reference is no longer available")
	}
	keyTypes := getServerKeyTypes()
	header := titleStyle.Render("Generate Cosigned Account") + "\n\n" +
		"Cosigner: " + reference.Name + "  " + apadminapp.CompactWitnessKeyID(reference.ComponentKey) + "\n\n" +
		"Choose a compatible account key type:\n\n"
	var rows []string
	selected := 0
	for row, index := range m.cosigner.generateTypeIndices {
		if index < 0 || index >= len(keyTypes) {
			continue
		}
		label := displayKeyType(keyTypes[index].KeyType)
		if row == m.cosigner.generateTypeSelected {
			selected = len(rows)
			rows = append(rows, selectedStyle.Render("> "+label))
		} else {
			rows = append(rows, "  "+label)
		}
	}
	return m.renderPopup(80, m.fitSelectionList(header, rows, selected, "", 80))
}

func (m Model) renderCosignerRemoveConfirm() string {
	var body strings.Builder
	body.WriteString(warningStyle.Render("REMOVE COSIGNER REFERENCE"))
	body.WriteString("\n\n")
	if reference, ok := m.cosignerRemovalReference(); ok {
		body.WriteString("Remove alias " + reference.Name + " from cosigned-account generation?\n\n")
		body.WriteString("Witness Key ID:\n")
		body.WriteString(wrapPlainText(groupedWitnessKeyID(reference.ComponentKey), m.popupBodyWidth(80)))
	} else if bad, ok := m.cosignerRemovalFile(); ok {
		body.WriteString(wrapPlainText(terminalSafe("Remove "+filepath.Base(bad.Path)+"? It is not a valid reference:"), m.popupBodyWidth(80)))
		body.WriteString("\n\n")
		body.WriteString(wrapPlainText(terminalSafe(bad.Reason), m.popupBodyWidth(80)))
	} else {
		return m.renderPopup(70, "Cosigner reference is no longer available")
	}
	body.WriteString("\n\n")
	body.WriteString(buttonPair(m.cosigner.removeFocus, "CANCEL", "REMOVE", buttonDanger))
	body.WriteString("\n")
	if m.cosigner.importError != "" {
		body.WriteString("\n" + errorStyle.Render(terminalSafeLines(m.cosigner.importError)) + "\n")
	}
	return m.renderPopup(80, body.String())
}

func (m Model) renderCosignerRemoving() string {
	return m.renderPopup(60, titleStyle.Render("Removing Cosigner Reference")+"\n\n"+subtitleStyle.Render("Please wait...")+"\n")
}
