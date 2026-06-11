// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

// Guard-group editor field plumbing: cursor/cell accessors,
// text input handling, hints, and display values.

import (
	"fmt"
	"strings"
)

func (m *Model) backspaceEditField() {
	value, ok := m.currentEditValue()
	if !ok || value == "" {
		return
	}
	runes := []rune(value)
	m.setCurrentEditValue(string(runes[:len(runes)-1]))
}

func (m *Model) clearEditField() {
	m.setCurrentEditValue("")
}

func (m Model) currentEditField() *routeEditField {
	if m.editCursor < 0 || m.editCursor >= len(m.editFields) {
		return nil
	}
	return &m.editFields[m.editCursor]
}

func (m Model) routeEditItemCount() int {
	return len(m.editFields) + len(m.editAssetRows)*routeEditAssetColumnCount
}

func (m Model) currentAssetCell() (int, string, bool) {
	cell := m.editCursor - len(m.editFields)
	if cell < 0 {
		return 0, "", false
	}
	row := cell / routeEditAssetColumnCount
	col := cell % routeEditAssetColumnCount
	if row < 0 || row >= len(m.editAssetRows) {
		return 0, "", false
	}
	switch col {
	case 0:
		return row, "asset", true
	case 1:
		return row, "review_above", true
	default:
		return row, "reject_above", true
	}
}

func (m Model) currentEditKey() string {
	if field := m.currentEditField(); field != nil {
		return field.key
	}
	_, col, ok := m.currentAssetCell()
	if !ok {
		return ""
	}
	return col
}

func (m Model) currentEditLabel() string {
	if field := m.currentEditField(); field != nil {
		return field.label
	}
	row, col, ok := m.currentAssetCell()
	if !ok {
		return "Field"
	}
	switch col {
	case "asset":
		return fmt.Sprintf("Asset %d", row+1)
	case "review_above":
		return fmt.Sprintf("Review Above %d", row+1)
	default:
		return fmt.Sprintf("Reject Above %d", row+1)
	}
}

func (m Model) currentEditValue() (string, bool) {
	if field := m.currentEditField(); field != nil {
		return field.value, true
	}
	row, col, ok := m.currentAssetCell()
	if !ok {
		return "", false
	}
	switch col {
	case "asset":
		return m.editAssetRows[row].asset, true
	case "review_above":
		return m.editAssetRows[row].reviewAbove, true
	default:
		return m.editAssetRows[row].rejectAbove, true
	}
}

func (m *Model) setCurrentEditValue(value string) {
	if m.editCursor >= 0 && m.editCursor < len(m.editFields) {
		m.editFields[m.editCursor].value = value
		return
	}
	row, col, ok := m.currentAssetCell()
	if !ok {
		return
	}
	switch col {
	case "asset":
		m.editAssetRows[row].asset = value
	case "review_above":
		m.editAssetRows[row].reviewAbove = value
	default:
		m.editAssetRows[row].rejectAbove = value
	}
}

func (m *Model) addEditAssetRow() {
	insertAt := len(m.editAssetRows)
	if row, _, ok := m.currentAssetCell(); ok {
		insertAt = row + 1
	}
	newRow := routeEditAssetRow{asset: "algo"}
	m.editAssetRows = append(m.editAssetRows, routeEditAssetRow{})
	copy(m.editAssetRows[insertAt+1:], m.editAssetRows[insertAt:])
	m.editAssetRows[insertAt] = newRow
	m.editCursor = len(m.editFields) + insertAt*routeEditAssetColumnCount
	m.status = "added asset row"
	m.err = ""
}

func (m *Model) deleteCurrentEditAssetRow() {
	row, _, ok := m.currentAssetCell()
	if !ok {
		m.status = "select an asset row to delete"
		return
	}
	if len(m.editAssetRows) <= 1 {
		m.status = "guard requires at least one asset row"
		return
	}
	copy(m.editAssetRows[row:], m.editAssetRows[row+1:])
	m.editAssetRows = m.editAssetRows[:len(m.editAssetRows)-1]
	if m.editCursor >= m.routeEditItemCount() {
		m.editCursor = m.routeEditItemCount() - 1
	}
	m.status = "deleted asset row"
	m.err = ""
}

func (m Model) currentRouteListField() *routeEditField {
	field := m.currentEditField()
	if field == nil || !isRouteListField(field.key) {
		return nil
	}
	return field
}

func (m Model) currentListEditField() *routeEditField {
	switch m.screen {
	case screenBlockedDestinationsEdit:
		return m.currentBlockedDestinationsListField()
	default:
		return m.currentRouteListField()
	}
}

func (m *Model) appendRouteListInput(input string) {
	field := m.currentListEditField()
	if field == nil {
		return
	}
	value := routeListEditValue(field.value)
	for _, r := range input {
		switch {
		case r == '\r':
			continue
		case r == '\n' || r == ',' || r == ' ':
			value = appendTermSeparator(value)
		case isRouteListRune(r):
			value += string(r)
		}
	}
	field.value = value
	m.ensureRouteListInputVisible()
}

func (m *Model) backspaceRouteListInput() {
	field := m.currentListEditField()
	if field == nil {
		return
	}
	value := routeListEditValue(field.value)
	if value == "" {
		field.value = ""
		m.editListOffset = 0
		return
	}
	runes := []rune(value)
	field.value = string(runes[:len(runes)-1])
	m.ensureRouteListInputVisible()
}

func (m *Model) clearRouteListInput() {
	field := m.currentListEditField()
	if field == nil {
		return
	}
	field.value = ""
	m.editListOffset = 0
}

func (m *Model) ensureRouteListInputVisible() {
	m.editListOffset = m.routeListMaxOffset()
}

func (m Model) routeListMaxOffset() int {
	field := m.currentListEditField()
	if field == nil {
		return 0
	}
	return maxOffsetForLines(routeListLines(field.value), m.routeListVisibleLines())
}

func (m Model) routeListVisibleLines() int {
	if m.height <= 0 {
		return 6
	}
	visible := m.height - m.appChromeLines() - m.routeListChromeLines()
	if visible < 3 {
		return 3
	}
	if visible > 8 {
		return 8
	}
	return visible
}

func (m Model) routeListChromeLines() int {
	// Popup title, spacer, entries, hint, spacer, input frame, spacer, help,
	// and popup border/padding.
	return 9 + inputActiveStyle.GetVerticalFrameSize() + popupStyle.GetVerticalFrameSize()
}

func (m Model) routeListInputWidth() int {
	width := m.popupBodyWidth(80) - inputActiveStyle.GetHorizontalFrameSize()
	if width < 20 {
		return 20
	}
	return width
}

func (m *Model) appendRouteTextInput(input string) {
	key := m.currentEditKey()
	value, ok := m.currentEditValue()
	if !ok {
		return
	}
	for _, r := range input {
		if isRouteTextRune(key, r) {
			value += string(r)
		}
	}
	m.setCurrentEditValue(value)
}

func (m Model) routeTextInputWidth() int {
	width := m.popupBodyWidth(80) - inputActiveStyle.GetHorizontalFrameSize()
	if width < 20 {
		return 20
	}
	return width
}

func (m Model) routeTextDisplayValue(value string) string {
	width := m.routeTextInputWidth()
	if width < 1 {
		return ""
	}
	cursor := "_"
	runes := []rune(value)
	if len(runes) >= width {
		runes = runes[len(runes)-width+1:]
	}
	return string(runes) + cursor
}

func routeEditFieldDisplayValue(field routeEditField) string {
	if isRouteListField(field.key) {
		terms := parseCSV(field.value)
		if len(terms) == 1 {
			return ellipsize(terms[0], 48)
		}
		return fmt.Sprintf("%d", len(terms))
	}
	return ellipsize(field.value, 48)
}

func routeEditorKind(key string) string {
	switch key {
	case "networks", "sources", "destinations":
		return "list"
	case "enabled", "close_allow":
		return "choice"
	default:
		return "text"
	}
}

func isRouteListField(key string) bool {
	return routeEditorKind(key) == "list"
}

func routeChoiceOptionsForKey(key string) []string {
	if key == "" {
		return nil
	}
	switch key {
	case "enabled", "close_allow":
		return []string{"true", "false"}
	default:
		return nil
	}
}

func routeListHint(key string) string {
	switch key {
	case "networks":
		return "One entry per line. Use network context tokens or *."
	case "sources":
		return "One entry per line. Supports addresses, @address_set, or *."
	case "destinations":
		return "One entry per line. Supports addresses, @address_set, self, or *."
	default:
		return "One entry per line."
	}
}

func (m Model) routeTextHint(key string) string {
	switch key {
	case "id":
		return "Route ID. Use lowercase letters, digits, underscore, or hyphen."
	case "description":
		return "Optional operator-facing note."
	case "asset":
		hint := "Use algo, an ASA ID, asa:<id>, cached symbol, asset set name, or *."
		if sets := m.assetSetReferenceSummary(); sets != "" {
			hint += " Defined asset sets: " + sets + "."
		}
		return hint
	case "review_above", "reject_above":
		return m.guardAmountHint(m.currentEditAmountAsset(), parseCSV(routeEditFieldValue(m.editFields, "networks")))
	default:
		return "Enter a value."
	}
}

func (m Model) currentEditAmountAsset() string {
	row, _, ok := m.currentAssetCell()
	if ok && row >= 0 && row < len(m.editAssetRows) {
		return m.editAssetRows[row].asset
	}
	return "algo"
}

func routeEditFieldValue(fields []routeEditField, key string) string {
	for _, field := range fields {
		if field.key == key {
			return field.value
		}
	}
	return ""
}

func routeListStorageValue(terms []string) string {
	return strings.Join(terms, "\n")
}

func routeListEditValue(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	if strings.TrimSpace(value) == "-" {
		return ""
	}
	if strings.Contains(value, "\n") {
		return value
	}
	return routeListStorageValue(parseCSV(value))
}

func routeListLines(value string) []string {
	lines := strings.Split(routeListEditValue(value), "\n")
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func appendTermSeparator(value string) string {
	value = strings.TrimRight(value, "\n")
	if value == "" {
		return value
	}
	return value + "\n"
}

func isRouteListRune(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '@' || r == '_' || r == '-' || r == '*' || r == ':'
}

func isRouteTextRune(key string, r rune) bool {
	switch key {
	case "review_above", "reject_above":
		return (r >= '0' && r <= '9') || r == '.'
	case "id":
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-'
	default:
		return r >= 32 && r <= 126
	}
}
