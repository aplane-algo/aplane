// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

// Guard-group editor screens: field grid, list/text/choice
// sub-editors, and conversion back to stored routes.

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
)

type routeEditAssetRow struct {
	routeIndex  int
	routeID     string
	asset       string
	reviewAbove string
	rejectAbove string
}

const routeEditAssetColumnCount = 3

func (m Model) handleRouteEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc":
		if m.busy {
			m.cancelFormApply()
		}
		m.screen = screenRoutes
		m.status = "guard list"
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "n":
		m.addEditAssetRow()
		return m, nil
	case "x", "d":
		before := len(m.editAssetRows)
		m.deleteCurrentEditAssetRow()
		if len(m.editAssetRows) == before {
			return m, nil
		}
		return m.applyRouteEdit()
	}
	switch msg.Type {
	case tea.KeyUp:
		if m.editCursor > 0 {
			m.editCursor--
		}
	case tea.KeyDown, tea.KeyTab, tea.KeyRight:
		if m.editCursor < m.routeEditItemCount()-1 {
			m.editCursor++
		}
	case tea.KeyLeft, tea.KeyShiftTab:
		if m.editCursor > 0 {
			m.editCursor--
		}
	case tea.KeyBackspace, tea.KeyDelete:
		m.status = "press enter to edit this field"
	case tea.KeyCtrlU:
		m.status = "press enter to edit this field"
	case tea.KeyEnter:
		return m.openRouteFieldEditor(), nil
	case tea.KeyRunes:
		m.status = "press enter to edit this field"
	}
	return m, nil
}

func (m Model) handleRouteListEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "b":
		m.screen = screenRouteEdit
		m.editListOffset = 0
		m.err = ""
		return m.applyRouteEdit()
	case "up", "k":
		if m.editListOffset > 0 {
			m.editListOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := m.routeListMaxOffset()
		if m.editListOffset < maxOffset {
			m.editListOffset++
		}
		return m, nil
	case "pgup":
		m.editListOffset -= m.routeListVisibleLines()
		if m.editListOffset < 0 {
			m.editListOffset = 0
		}
		return m, nil
	case "pgdown":
		maxOffset := m.routeListMaxOffset()
		m.editListOffset += m.routeListVisibleLines()
		if m.editListOffset > maxOffset {
			m.editListOffset = maxOffset
		}
		return m, nil
	case "home":
		m.editListOffset = 0
		return m, nil
	case "end":
		m.editListOffset = m.routeListMaxOffset()
		return m, nil
	}

	switch msg.Type {
	case tea.KeyBackspace, tea.KeyDelete:
		m.backspaceRouteListInput()
	case tea.KeyCtrlU:
		m.clearRouteListInput()
	case tea.KeyEnter:
		m.appendRouteListInput("\n")
	case tea.KeyRunes:
		m.appendRouteListInput(string(msg.Runes))
	}
	return m, nil
}

func (m Model) handleRouteTextEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "enter":
		m.screen = screenRouteEdit
		m.err = ""
		return m.applyRouteEdit()
	}
	switch msg.Type {
	case tea.KeyBackspace, tea.KeyDelete:
		m.backspaceEditField()
	case tea.KeyCtrlU:
		m.clearEditField()
	case tea.KeySpace:
		m.appendRouteTextInput(" ")
	case tea.KeyRunes:
		m.appendRouteTextInput(string(msg.Runes))
	}
	return m, nil
}

func (m Model) handleRouteChoiceEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.currentEditKey()
	choices := routeChoiceOptionsForKey(key)
	if len(choices) == 0 {
		m.screen = screenRouteEdit
		m.status = "guard edit"
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "b":
		m.screen = screenRouteEdit
		m.status = "guard edit"
		m.err = ""
		return m, nil
	case "up", "k":
		if m.editChoiceCursor > 0 {
			m.editChoiceCursor--
		}
		return m, nil
	case "down", "j", "tab":
		if m.editChoiceCursor < len(choices)-1 {
			m.editChoiceCursor++
		}
		return m, nil
	case "home":
		m.editChoiceCursor = 0
		return m, nil
	case "end":
		m.editChoiceCursor = len(choices) - 1
		return m, nil
	case "enter", " ", "space":
		m.setCurrentEditValue(choices[m.editChoiceCursor])
		m.screen = screenRouteEdit
		m.err = ""
		return m.applyRouteEdit()
	}
	return m, nil
}

func (m Model) routeEditView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Edit Transfer Guard"))
	b.WriteString("\n\n")
	b.WriteString(descriptionStyle.Render("Enter opens the selected editor. Each asset row is stored as one guard_asset route."))
	b.WriteString("\n\n")
	for i, field := range m.editFields {
		line := fmt.Sprintf("%-16s %s", field.label, routeEditFieldDisplayValue(field))
		if i == m.editCursor {
			b.WriteString(selectedStyle.Render("  " + line + "  "))
		} else {
			b.WriteString("  " + line)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(metadataStyle.Render("Assets"))
	b.WriteString("\n")
	b.WriteString(m.renderAssetEditHeader())
	for i, row := range m.editAssetRows {
		b.WriteString(m.renderAssetEditRow(i, row))
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down/left/right move  enter edit  n add asset  x delete asset  esc back\n")
	return m.renderHelp(b.String())
}

func (m Model) renderAssetEditHeader() string {
	widths := m.routeAssetEditColumnWidths()
	labels := []string{"Asset", "Review Above", "Reject Above"}
	parts := make([]string, 0, len(labels))
	for i, label := range labels {
		parts = append(parts, fixedWidthFieldLine(ellipsize(label, widths[i]), widths[i]))
	}
	return "  " + metadataStyle.Render(strings.Join(parts, " ")) + "\n"
}

func (m Model) renderAssetEditRow(rowIndex int, row routeEditAssetRow) string {
	cells := []string{
		routeAssetCellDisplay(row.asset),
		routeAssetCellDisplay(row.reviewAbove),
		routeAssetCellDisplay(row.rejectAbove),
	}
	widths := m.routeAssetEditColumnWidths()
	var parts []string
	for col := 0; col < len(cells); col++ {
		selected := m.editCursor == len(m.editFields)+rowIndex*routeEditAssetColumnCount+col
		cell := fixedWidthFieldLine(ellipsize(cells[col], widths[col]), widths[col])
		if selected {
			cell = selectedStyle.Render(cell)
		}
		parts = append(parts, cell)
	}
	return "  " + strings.Join(parts, " ")
}

func (m Model) routeAssetEditColumnWidths() []int {
	available := m.panelWidth() - 8
	if available < 34 {
		available = 34
	}
	widths := []int{10, 10, 10}
	extra := available - 2 - 30
	grow := []int{24, 6, 6}
	for i := range widths {
		if extra <= 0 {
			break
		}
		add := grow[i]
		if add > extra {
			add = extra
		}
		widths[i] += add
		extra -= add
	}
	return widths
}

func routeAssetCellDisplay(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func (m Model) routeListEditView() string {
	field := m.currentRouteListField()
	title := "Edit List"
	if field != nil {
		title = "Edit " + field.label
	}

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	if field == nil {
		b.WriteString(statusErrorStyle.Render("No list field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}

	terms := parseCSV(field.value)
	b.WriteString(metadataStyle.Render(fmt.Sprintf("entries: %d", len(terms))))
	b.WriteString("\n")
	b.WriteString(descriptionStyle.Render(routeListHint(field.key)))
	b.WriteString("\n\n")
	b.WriteString(m.routeListInputBox(field.value))
	b.WriteString("\n\n")
	b.WriteString("keys: type edit  comma/space/enter new entry  backspace delete  ctrl+u clear  up/down/pgup/pgdown scroll  esc done\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) routeListInputBox(value string) string {
	lines := routeListLines(value)
	if len(lines) == 0 {
		lines = []string{""}
	}
	if m.screen == screenRouteListEdit || m.screen == screenBlockedDestinationsEdit {
		lines = append([]string(nil), lines...)
		lines[len(lines)-1] += "_"
	}

	visibleLines := m.routeListVisibleLines()
	offset := m.editListOffset
	maxOffset := maxOffsetForLines(lines, visibleLines)
	if offset < 0 {
		offset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}
	end := offset + visibleLines
	if end > len(lines) {
		end = len(lines)
	}

	var b strings.Builder
	if offset > 0 {
		b.WriteString(scrollMoreAboveLine(offset))
		b.WriteString("\n")
	}
	displayLines := append([]string(nil), lines[offset:end]...)
	for len(displayLines) < visibleLines {
		displayLines = append(displayLines, "")
	}
	width := m.routeListInputWidth()
	for i, line := range displayLines {
		displayLines[i] = fixedWidthFieldLine(line, width)
	}
	b.WriteString(inputActiveStyle.Render(strings.Join(displayLines, "\n")))
	if end < len(lines) {
		b.WriteString("\n")
		b.WriteString(scrollMoreBelowLine(len(lines) - end))
	}
	return b.String()
}

func (m Model) routeTextEditView() string {
	key := m.currentEditKey()
	title := "Edit Text"
	if key != "" {
		title = "Edit " + m.currentEditLabel()
	}

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	value, ok := m.currentEditValue()
	if key == "" || !ok {
		b.WriteString(statusErrorStyle.Render("No text field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}
	b.WriteString(descriptionStyle.Render(m.routeTextHint(key)))
	b.WriteString("\n\n")
	b.WriteString(inputActiveStyle.Render(fixedWidthFieldLine(m.routeTextDisplayValue(value), m.routeTextInputWidth())))
	b.WriteString("\n\n")
	b.WriteString("keys: type edit  backspace delete  ctrl+u clear  enter/esc done\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) routeChoiceEditView() string {
	key := m.currentEditKey()
	title := "Choose Value"
	if key != "" {
		title = "Choose " + m.currentEditLabel()
	}
	choices := routeChoiceOptionsForKey(key)

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	if key == "" || len(choices) == 0 {
		b.WriteString(statusErrorStyle.Render("No choice field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}
	for i, choice := range choices {
		line := "  " + choice
		if i == m.editChoiceCursor {
			b.WriteString(selectedStyle.Render(line + "  "))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down move  enter/space select  esc cancel\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) openGuardGroupEditor(group transferGuardGroup) Model {
	if group.Advanced {
		m.status = "advanced route is YAML-only; press y to inspect or edit"
		m.err = group.AdvancedReason
		return m
	}
	for _, row := range group.AssetRows {
		if row.ReviewAbove != nil || row.RejectAbove != nil {
			if _, _, err := m.guardAmountMetadata(row.Asset, group.Networks, true); err != nil {
				m.status = "guard amount metadata unavailable; press y to inspect or edit"
				m.err = err.Error()
				return m
			}
		}
	}
	m.screen = screenRouteEdit
	m.editGroupIndex = group.Index
	m.editRouteIndex = -1
	if len(group.RouteIndexes) > 0 {
		m.editRouteIndex = group.RouteIndexes[0]
	}
	m.editCursor = 0
	m.editFields = m.guardGroupToEditFields(group)
	m.editAssetRows = m.guardGroupToEditAssetRows(group)
	m.status = fmt.Sprintf("editing guard %s", group.ID)
	m.err = ""
	return m
}

func (m Model) guardGroupToEditFields(group transferGuardGroup) []routeEditField {
	return []routeEditField{
		{key: "id", label: "Name", value: group.ID},
		{key: "description", label: "Description", value: group.Description},
		{key: "enabled", label: "Enabled", value: boolValueWithDefault(group.Enabled, true)},
		{key: "networks", label: "Networks", value: joinTerms(group.Networks)},
		{key: "sources", label: "Sources", value: joinTerms(group.Sources)},
		{key: "destinations", label: "Destinations", value: joinTerms(group.Destinations)},
		{key: "close_allow", label: "Close Allow", value: boolValueWithDefault(group.CloseAllow, false)},
	}
}

func (m Model) guardGroupToEditAssetRows(group transferGuardGroup) []routeEditAssetRow {
	rows := make([]routeEditAssetRow, 0, len(group.AssetRows))
	for _, row := range group.AssetRows {
		rows = append(rows, routeEditAssetRow{
			routeIndex:  row.RouteIndex,
			routeID:     row.RouteID,
			asset:       row.Asset,
			reviewAbove: m.formatOptionalGuardAmount(row.ReviewAbove, row.Asset, group.Networks),
			rejectAbove: m.formatOptionalGuardAmount(row.RejectAbove, row.Asset, group.Networks),
		})
	}
	return rows
}

func (m Model) openRouteFieldEditor() Model {
	key := m.currentEditKey()
	if key == "" {
		m.status = "select a field to edit"
		return m
	}
	switch routeEditorKind(key) {
	case "list":
		return m.openRouteListEditor()
	case "choice":
		return m.openRouteChoiceEditor()
	default:
		return m.openRouteTextEditor()
	}
}

func (m Model) openRouteListEditor() Model {
	field := m.currentRouteListField()
	if field == nil {
		m.status = "select a list field to edit"
		return m
	}
	m.screen = screenRouteListEdit
	m.editListOffset = 0
	field.value = routeListStorageValue(parseCSV(field.value))
	if field.value != "" {
		field.value += "\n"
	}
	m.status = "editing " + strings.ToLower(field.label)
	m.err = ""
	return m
}

func (m Model) openRouteTextEditor() Model {
	if m.currentEditKey() == "" {
		m.status = "select a text field to edit"
		return m
	}
	m.screen = screenRouteTextEdit
	m.status = "editing " + strings.ToLower(m.currentEditLabel())
	m.err = ""
	return m
}

func (m Model) openRouteChoiceEditor() Model {
	key := m.currentEditKey()
	choices := routeChoiceOptionsForKey(key)
	if key == "" || len(choices) == 0 {
		m.status = "select a choice field to edit"
		return m
	}
	m.screen = screenRouteChoiceEdit
	m.editChoiceCursor = 0
	current, _ := m.currentEditValue()
	current = strings.TrimSpace(current)
	for i, choice := range choices {
		if choice == current {
			m.editChoiceCursor = i
			break
		}
	}
	m.status = "choosing " + strings.ToLower(m.currentEditLabel())
	m.err = ""
	return m
}

func (m Model) applyRouteEdit() (tea.Model, tea.Cmd) {
	routes, err := m.editFieldsToGuardGroupRoutes()
	if err != nil {
		m.err = err.Error()
		m.status = "guard parse failed"
		return m, nil
	}
	draft, err := m.policyWithEditedGuardGroup(routes)
	if err != nil {
		m.err = err.Error()
		m.status = "guard save failed"
		return m, nil
	}
	m.busy = true
	m.formApplyToken++
	token := m.formApplyToken
	m.err = ""
	m.status = "validating guard"
	return m, func() tea.Msg {
		return routeApplyResultMsg{token: token, groupIndex: m.editGroupIndex, routes: routes, err: m.store.Validate(context.Background(), draft)}
	}
}

func (m Model) editFieldsToGuardGroupRoutes() ([]policy.StoredTransferRoute, error) {
	values := editFieldValues(m.editFields)
	guardName := strings.TrimSpace(values["id"])
	if guardName == "" {
		return nil, fmt.Errorf("name is required")
	}
	enabled, err := parseOptionalBool(values["enabled"])
	if err != nil {
		return nil, fmt.Errorf("enabled: %w", err)
	}
	closeAllow, err := parseOptionalBool(values["close_allow"])
	if err != nil {
		return nil, fmt.Errorf("close_allow: %w", err)
	}
	networks := parseCSV(values["networks"])
	group := transferGuardGroup{
		Index:        m.editGroupIndex,
		ID:           guardName,
		Description:  strings.TrimSpace(values["description"]),
		Enabled:      enabled,
		Networks:     networks,
		Sources:      parseCSV(values["sources"]),
		Destinations: parseCSV(values["destinations"]),
		CloseAllow:   closeAllow,
	}
	if len(m.editAssetRows) == 0 {
		return nil, fmt.Errorf("at least one asset row is required")
	}

	seen := m.routeIDSetExcludingEditedGroup()
	for i, editRow := range m.editAssetRows {
		asset, err := m.normalizeGuardAsset(editRow.asset, networks)
		if err != nil {
			return nil, fmt.Errorf("asset row %d asset: %w", i+1, err)
		}
		if asset == "" {
			return nil, fmt.Errorf("asset row %d asset is required", i+1)
		}
		reviewAbove, err := m.parseOptionalGuardAmount(editRow.reviewAbove, asset, networks)
		if err != nil {
			return nil, fmt.Errorf("asset row %d review_above: %w", i+1, err)
		}
		rejectAbove, err := m.parseOptionalGuardAmount(editRow.rejectAbove, asset, networks)
		if err != nil {
			return nil, fmt.Errorf("asset row %d reject_above: %w", i+1, err)
		}
		id := m.editedAssetRouteID(guardName, asset, editRow)
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("asset row %d route id %q is already in use", i+1, id)
		}
		seen[id] = struct{}{}
		group.AssetRows = append(group.AssetRows, transferGuardAssetRow{
			RouteIndex:  editRow.routeIndex,
			RouteID:     id,
			Asset:       asset,
			ReviewAbove: reviewAbove,
			RejectAbove: rejectAbove,
		})
	}
	return guardGroupToRoutes(group, m.routes())
}

func (m Model) editedAssetRouteID(guardName, asset string, editRow routeEditAssetRow) string {
	routes := m.routes()
	if editRow.routeIndex >= 0 && editRow.routeIndex < len(routes) {
		return guardRouteIDForExisting(guardName, asset, &routes[editRow.routeIndex])
	}
	if editRow.routeID != "" {
		return editRow.routeID
	}
	return guardRouteID(guardName, asset)
}

func editFieldValues(fields []routeEditField) map[string]string {
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		values[field.key] = strings.TrimSpace(field.value)
	}
	return values
}

func (m Model) routeIDSetExcludingEditedGroup() map[string]struct{} {
	routes := m.routes()
	seen := routeIDSet(routes)
	groups := transferGuardGroups(routes)
	if m.editGroupIndex < 0 || m.editGroupIndex >= len(groups) {
		return seen
	}
	for _, index := range groups[m.editGroupIndex].RouteIndexes {
		if index >= 0 && index < len(routes) {
			delete(seen, routes[index].ID)
		}
	}
	return seen
}

func (m Model) policyWithEditedGuardGroup(routes []policy.StoredTransferRoute) (*policy.StoredConfig, error) {
	draft, _, err := m.cloneStored(m.policy)
	if err != nil {
		return nil, err
	}
	if draft.TransferPolicy == nil {
		return nil, fmt.Errorf("transfer policy is not initialized")
	}
	groups := transferGuardGroups(draft.TransferPolicy.Routes)
	if m.editGroupIndex < 0 || m.editGroupIndex >= len(groups) {
		return nil, fmt.Errorf("route index is no longer valid")
	}
	start, end := guardGroupRouteRange(groups[m.editGroupIndex])
	updated := removeRouteBlock(draft.TransferPolicy.Routes, start, end)
	draft.TransferPolicy.Routes = insertRoutes(updated, start, routes)
	draft.TransferPolicy.RoutesSet = true
	return draft, nil
}
