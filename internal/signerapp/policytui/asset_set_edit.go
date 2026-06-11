// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

// Asset-set screens: list, editor grid, text sub-editor, and
// asset-set mutations on the stored policy.

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
)

func (m Model) handleAssetSetKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m.requestQuit()
	case "esc", "b", "backspace":
		m.screen = screenRoutes
		m.status = "guard list"
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	rows := m.assetSetRows()
	switch msg.String() {
	case "up", "k":
		if m.assetSetCursor > 0 {
			m.assetSetCursor--
		}
	case "down", "j":
		if m.assetSetCursor < len(rows)-1 {
			m.assetSetCursor++
		}
	case "enter", "e":
		if len(rows) == 0 {
			m.status = "no asset sets to edit"
			return m, nil
		}
		return m.openAssetSetEditor(rows[m.assetSetCursor]), nil
	case "n":
		return m.openNewAssetSetEditor(), nil
	case "c":
		if len(rows) == 0 {
			m.status = "no asset set to clone"
			return m, nil
		}
		return m.openClonedAssetSetEditor(rows[m.assetSetCursor]), nil
	case "d", "x":
		if len(rows) == 0 {
			m.status = "no asset set to delete"
			return m, nil
		}
		m.screen = screenDeleteAssetSetConfirm
		m.deleteAssetSetName = rows[m.assetSetCursor].Name
		m.status = fmt.Sprintf("confirm delete asset set %s", m.deleteAssetSetName)
		m.err = ""
	case "y", "Y":
		m.screen = screenRouteYAML
		m.routeYAMLOffset = 0
		m.status = "transfer policy yaml"
		m.err = ""
	case "a":
		return m.applyProduction()
	case "w":
		return m.openWriteFile()
	case "v":
		return m.validate()
	}
	return m, nil
}

func (m Model) handleAssetSetEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "b", "backspace":
		if m.busy {
			m.cancelFormApply()
		}
		m.screen = screenAssetSets
		m.status = "asset sets"
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "up", "k":
		m.moveAssetSetEditCursor(-1)
	case "down", "j":
		m.moveAssetSetEditCursor(1)
	case "left", "h":
		m.moveAssetSetEditCursor(-1)
	case "right", "l", "tab":
		m.moveAssetSetEditCursor(1)
	case "enter", "e":
		return m.openAssetSetFieldEditor(), nil
	case "n":
		m.addAssetSetNetworkRow()
	case "x", "delete":
		before := len(m.editAssetSetRows)
		m.deleteCurrentAssetSetNetworkRow()
		if len(m.editAssetSetRows) == before {
			return m, nil
		}
		return m.applyAssetSetEdit()
	}
	return m, nil
}

func (m Model) handleAssetSetTextEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "enter":
		m.screen = screenAssetSetEdit
		m.err = ""
		return m.applyAssetSetEdit()
	}
	switch msg.Type {
	case tea.KeyBackspace, tea.KeyDelete:
		m.backspaceAssetSetTextInput()
	case tea.KeyCtrlU:
		m.setCurrentAssetSetEditValue("")
	case tea.KeyRunes:
		m.appendAssetSetTextInput(string(msg.Runes))
	}
	return m, nil
}

func (m Model) handleDeleteAssetSetConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "y", "d":
		return m.deleteSelectedAssetSetConfirmed()
	case "n", "esc", "b", "backspace":
		m.screen = screenAssetSets
		m.status = "delete canceled"
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) assetSetView() string {
	var b strings.Builder
	rows := m.assetSetRows()
	b.WriteString(sectionStyle.Render("Asset Sets"))
	b.WriteString("\n\n")
	if m.policy == nil || m.policy.TransferPolicy == nil {
		b.WriteString(readonlyStyle.Render("transfer routing is off; no stored asset sets are present"))
		b.WriteString("\n")
	} else if len(rows) == 0 {
		b.WriteString(readonlyStyle.Render("no stored asset sets"))
		b.WriteString("\n")
	} else {
		if m.assetSetCursor >= len(rows) {
			m.assetSetCursor = len(rows) - 1
		}
		for i, row := range rows {
			b.WriteString(m.renderAssetSetRow(i, row))
			b.WriteString("\n")
		}
	}
	b.WriteString("\nkeys: up/down move  enter/e edit set  n new  c clone  d delete  y yaml  v validate  w write draft  a apply production  b back  q quit\n")
	if m.modified() {
		b.WriteString(modifiedProductionWarning + "\n")
	}
	return m.renderHelp(b.String())
}

func (m Model) assetSetEditView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Edit Asset Set"))
	b.WriteString("\n\n")
	nameLine := fmt.Sprintf("%-12s %s", "Name", assetSetEditDisplayValue("name", m.editAssetSetName))
	if m.editCursor == 0 {
		b.WriteString(selectedStyle.Render("  " + nameLine + "  "))
	} else {
		b.WriteString("  " + nameLine)
	}
	b.WriteString("\n\n")
	b.WriteString(metadataStyle.Render("Network mappings"))
	b.WriteString("\n")
	b.WriteString(m.renderAssetSetEditHeader())
	for i, row := range m.editAssetSetRows {
		b.WriteString(m.renderAssetSetEditRow(i, row))
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down/left/right move  enter edit  n add network  x delete network  esc back\n")
	return m.renderHelp(b.String())
}

func (m Model) renderAssetSetEditHeader() string {
	return "  " + metadataStyle.Render(fmt.Sprintf("%-18s %-32s", "Network", "ASA IDs")) + "\n"
}

func (m Model) renderAssetSetEditRow(rowIndex int, row assetSetEditRow) string {
	cells := []struct {
		key   string
		value string
		width int
	}{
		{key: "network", value: row.Network, width: 18},
		{key: "asa_ids", value: assetSetEditDisplayValue("asa_ids", row.ASAIDs), width: 32},
	}
	var parts []string
	for col, cell := range cells {
		selected := m.editCursor == 1+rowIndex*2+col
		line := fixedWidthFieldLine(ellipsize(cell.value, cell.width), cell.width)
		if selected {
			line = selectedStyle.Render(line)
		}
		parts = append(parts, line)
	}
	return "  " + strings.Join(parts, " ")
}

func (m Model) assetSetTextEditView() string {
	title := "Edit " + m.currentAssetSetEditLabel()
	value, ok := m.currentAssetSetEditValue()

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	if !ok {
		b.WriteString(statusErrorStyle.Render("No text field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}
	b.WriteString(descriptionStyle.Render(m.assetSetTextHint(m.currentAssetSetEditKey())))
	b.WriteString("\n\n")
	b.WriteString(inputActiveStyle.Render(fixedWidthFieldLine(m.assetSetTextDisplayValue(value), m.routeTextInputWidth())))
	b.WriteString("\n\n")
	b.WriteString("keys: type edit  backspace delete  ctrl+u clear  enter/esc done\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) deleteAssetSetConfirmView() string {
	name := m.deleteAssetSetName
	if strings.TrimSpace(name) == "" {
		name = "(missing)"
	}
	return m.renderHelp(renderLines(
		sectionStyle.Render("Delete Asset Set"),
		"",
		statusWarnStyle.Render("Delete asset set "+name+"?"),
		"",
		"This validates the policy draft before removing the set.",
		"Routes that still reference @"+name+" will block deletion.",
		"",
		"keys: y delete  n cancel  esc cancel",
	))
}

func (m Model) renderAssetSetRow(i int, row assetSetRow) string {
	line := fmt.Sprintf("%s  networks=%d assets=%d  %s", row.Name, row.NetworkCount, row.ASAIDCount, row.Preview)
	line = ellipsize(line, m.panelWidth()-6)
	if i == m.assetSetCursor {
		return selectedStyle.Render("  " + line + "  ")
	}
	return "  " + line
}

func (m Model) openAssetSets() Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.ensureTransferPolicy()
	}
	status := "asset sets"
	if m.seedDefaultAssetSets() {
		status = "added default usdc asset set"
	}
	m.screen = screenAssetSets
	m.assetSetCursor = 0
	m.status = status
	m.err = ""
	return m
}

func (m *Model) seedDefaultAssetSets() bool {
	if m.policy == nil || m.policy.TransferPolicy == nil || len(m.policy.TransferPolicy.AssetSets) > 0 {
		return false
	}
	defaults := defaultAssetSets()
	if len(defaults) == 0 {
		return false
	}
	m.policy.TransferPolicy.AssetSets = defaults
	return true
}

func (m Model) openAssetSetEditor(row assetSetRow) Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.status = "transfer policy is not initialized"
		return m
	}
	set := m.policy.TransferPolicy.AssetSets[row.Name]
	m.screen = screenAssetSetEdit
	m.editAssetSetIndex = row.Index
	m.editAssetSetOriginalName = row.Name
	m.editAssetSetName = row.Name
	m.editAssetSetRows = assetSetToEditRows(set)
	m.editCursor = 0
	m.editListOffset = 0
	m.status = fmt.Sprintf("editing asset set %s", row.Name)
	m.err = ""
	return m
}

func (m Model) openNewAssetSetEditor() Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.ensureTransferPolicy()
	}
	m.screen = screenAssetSetEdit
	m.editAssetSetIndex = -1
	m.editAssetSetOriginalName = ""
	name, rows := m.defaultNewAssetSet()
	m.editAssetSetName = name
	m.editAssetSetRows = rows
	m.editCursor = 0
	m.editListOffset = 0
	m.status = "editing new asset set"
	m.err = ""
	return m
}

func (m Model) defaultNewAssetSet() (string, []assetSetEditRow) {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return "usdc", assetSetToEditRows(defaultUSDCAssetSet())
	}
	if _, ok := m.policy.TransferPolicy.AssetSets["usdc"]; !ok {
		rows := assetSetToEditRows(defaultUSDCAssetSet())
		if len(rows) > 0 {
			return "usdc", rows
		}
	}
	return m.uniqueAssetSetName("asset_set"), []assetSetEditRow{{Network: "testnet"}}
}

func (m Model) openClonedAssetSetEditor(row assetSetRow) Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.status = "transfer policy is not initialized"
		return m
	}
	set := m.policy.TransferPolicy.AssetSets[row.Name]
	m.screen = screenAssetSetEdit
	m.editAssetSetIndex = -1
	m.editAssetSetOriginalName = ""
	m.editAssetSetName = m.uniqueAssetSetName(row.Name + "_copy")
	m.editAssetSetRows = assetSetToEditRows(set)
	m.editCursor = 0
	m.editListOffset = 0
	m.status = fmt.Sprintf("editing clone of asset set %s", row.Name)
	m.err = ""
	return m
}

func (m Model) policyWithEditedAssetSet(oldName, name string, set policy.StoredAssetSet) (*policy.StoredConfig, error) {
	draft, _, err := m.cloneStored(m.policy)
	if err != nil {
		return nil, err
	}
	if draft.TransferPolicy == nil {
		enabled := true
		onNoRoute := string(policy.TransferOnNoRouteReject)
		closeOnNoRoute := string(policy.TransferOnNoRouteReject)
		clawbackOnNoRoute := string(policy.TransferOnNoRouteReject)
		draft.TransferPolicy = &policy.StoredTransferPolicy{
			SchemaVersion:     1,
			Enabled:           &enabled,
			OnNoRoute:         &onNoRoute,
			CloseOnNoRoute:    &closeOnNoRoute,
			ClawbackOnNoRoute: &clawbackOnNoRoute,
			RoutesSet:         true,
		}
	}
	if draft.TransferPolicy.AssetSets == nil {
		draft.TransferPolicy.AssetSets = make(map[string]policy.StoredAssetSet)
	}
	if oldName != "" && oldName != name {
		delete(draft.TransferPolicy.AssetSets, oldName)
	}
	draft.TransferPolicy.AssetSets[name] = cloneAssetSet(set)
	return draft, nil
}

func (m Model) policyWithDeletedAssetSet(name string) (*policy.StoredConfig, error) {
	draft, _, err := m.cloneStored(m.policy)
	if err != nil {
		return nil, err
	}
	if draft.TransferPolicy == nil {
		return nil, fmt.Errorf("transfer policy is not initialized")
	}
	if _, ok := draft.TransferPolicy.AssetSets[name]; !ok {
		return nil, fmt.Errorf("asset set %s no longer exists", name)
	}
	delete(draft.TransferPolicy.AssetSets, name)
	if len(draft.TransferPolicy.AssetSets) == 0 {
		draft.TransferPolicy.AssetSets = nil
	}
	return draft, nil
}

func (m Model) assetSetEditItemCount() int {
	return 1 + len(m.editAssetSetRows)*2
}

func (m *Model) moveAssetSetEditCursor(delta int) {
	count := m.assetSetEditItemCount()
	if count <= 0 {
		m.editCursor = 0
		return
	}
	m.editCursor += delta
	if m.editCursor < 0 {
		m.editCursor = 0
	}
	if m.editCursor >= count {
		m.editCursor = count - 1
	}
}

func (m Model) currentAssetSetCell() (int, string, bool) {
	if m.editCursor == 0 {
		return 0, "name", true
	}
	cell := m.editCursor - 1
	row := cell / 2
	col := cell % 2
	if row < 0 || row >= len(m.editAssetSetRows) {
		return 0, "", false
	}
	if col == 0 {
		return row, "network", true
	}
	return row, "asa_ids", true
}

func (m Model) currentAssetSetEditKey() string {
	_, key, ok := m.currentAssetSetCell()
	if !ok {
		return ""
	}
	return key
}

func (m Model) currentAssetSetEditLabel() string {
	row, key, ok := m.currentAssetSetCell()
	if !ok {
		return "Field"
	}
	switch key {
	case "name":
		return "Name"
	case "network":
		return fmt.Sprintf("Network %d", row+1)
	default:
		return fmt.Sprintf("ASA IDs %d", row+1)
	}
}

func (m Model) currentAssetSetEditValue() (string, bool) {
	row, key, ok := m.currentAssetSetCell()
	if !ok {
		return "", false
	}
	switch key {
	case "name":
		return m.editAssetSetName, true
	case "network":
		return m.editAssetSetRows[row].Network, true
	default:
		return m.editAssetSetRows[row].ASAIDs, true
	}
}

func (m *Model) setCurrentAssetSetEditValue(value string) {
	row, key, ok := m.currentAssetSetCell()
	if !ok {
		return
	}
	switch key {
	case "name":
		m.editAssetSetName = value
	case "network":
		m.editAssetSetRows[row].Network = value
	case "asa_ids":
		m.editAssetSetRows[row].ASAIDs = value
	}
}

func (m Model) openAssetSetFieldEditor() Model {
	if m.currentAssetSetEditKey() == "" {
		m.status = "select a field to edit"
		return m
	}
	m.screen = screenAssetSetTextEdit
	m.status = "editing " + strings.ToLower(m.currentAssetSetEditLabel())
	m.err = ""
	return m
}

func (m *Model) addAssetSetNetworkRow() {
	insertAt := len(m.editAssetSetRows)
	if row, key, ok := m.currentAssetSetCell(); ok && key != "name" {
		insertAt = row + 1
	}
	m.editAssetSetRows = append(m.editAssetSetRows, assetSetEditRow{})
	copy(m.editAssetSetRows[insertAt+1:], m.editAssetSetRows[insertAt:])
	m.editAssetSetRows[insertAt] = assetSetEditRow{Network: "testnet"}
	m.editCursor = 1 + insertAt*2
	m.status = "added network row"
	m.err = ""
}

func (m *Model) deleteCurrentAssetSetNetworkRow() {
	row, key, ok := m.currentAssetSetCell()
	if !ok || key == "name" {
		m.status = "select a network row to delete"
		return
	}
	if len(m.editAssetSetRows) <= 1 {
		m.status = "asset set requires at least one network row"
		return
	}
	copy(m.editAssetSetRows[row:], m.editAssetSetRows[row+1:])
	m.editAssetSetRows = m.editAssetSetRows[:len(m.editAssetSetRows)-1]
	if m.editCursor >= m.assetSetEditItemCount() {
		m.editCursor = m.assetSetEditItemCount() - 1
	}
	m.status = "deleted network row"
	m.err = ""
}

func assetSetEditDisplayValue(key, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return ellipsize(value, 48)
}

func (m *Model) appendAssetSetTextInput(input string) {
	key := m.currentAssetSetEditKey()
	value, ok := m.currentAssetSetEditValue()
	if !ok {
		return
	}
	for _, r := range input {
		if isAssetSetTextRune(key, r) {
			value += string(r)
		}
	}
	m.setCurrentAssetSetEditValue(value)
}

func (m *Model) backspaceAssetSetTextInput() {
	value, ok := m.currentAssetSetEditValue()
	if !ok || value == "" {
		return
	}
	runes := []rune(value)
	m.setCurrentAssetSetEditValue(string(runes[:len(runes)-1]))
}

func (m Model) assetSetTextDisplayValue(value string) string {
	return m.routeTextDisplayValue(value)
}

func (m Model) assetSetTextHint(key string) string {
	switch key {
	case "name":
		return "Asset set name. Use lowercase letters, digits, underscore, or hyphen; routes reference it as @name."
	case "network":
		return "Network context token such as mainnet, testnet, or localnet. * is not valid for asset sets."
	case "asa_ids":
		return "Comma-separated ASA IDs. Use numeric IDs or asa:<id>."
	default:
		return "Enter a value."
	}
}

func isAssetSetTextRune(key string, r rune) bool {
	switch key {
	case "name":
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-'
	case "network":
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-'
	case "asa_ids":
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == ':' || r == ',' || r == ' '
	default:
		return r >= 32 && r <= 126
	}
}

func (m Model) applyAssetSetEdit() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.editAssetSetName)
	if err := validateAssetSetName(name); err != nil {
		m.err = err.Error()
		m.status = "asset set parse failed"
		return m, nil
	}
	set, err := editRowsToAssetSet(m.editAssetSetRows)
	if err != nil {
		m.err = err.Error()
		m.status = "asset set parse failed"
		return m, nil
	}
	draft, err := m.policyWithEditedAssetSet(m.editAssetSetOriginalName, name, set)
	if err != nil {
		m.err = err.Error()
		m.status = "asset set save failed"
		return m, nil
	}
	m.busy = true
	m.formApplyToken++
	token := m.formApplyToken
	oldName := m.editAssetSetOriginalName
	m.err = ""
	m.status = "validating asset set"
	return m, func() tea.Msg {
		return assetSetApplyResultMsg{
			token:   token,
			oldName: oldName,
			name:    name,
			set:     set,
			err:     m.store.Validate(context.Background(), draft),
		}
	}
}

func (m Model) deleteSelectedAssetSetConfirmed() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.deleteAssetSetName)
	if name == "" {
		m.screen = screenAssetSets
		m.status = "asset set no longer exists"
		return m, nil
	}
	draft, err := m.policyWithDeletedAssetSet(name)
	if err != nil {
		m.err = err.Error()
		m.status = "asset set delete failed"
		m.screen = screenAssetSets
		return m, nil
	}
	m.busy = true
	m.formApplyToken++
	token := m.formApplyToken
	m.err = ""
	m.status = "validating asset set delete"
	return m, func() tea.Msg {
		return assetSetDeleteResultMsg{
			token: token,
			name:  name,
			err:   m.store.Validate(context.Background(), draft),
		}
	}
}

func (m Model) uniqueAssetSetName(base string) string {
	seen := make(map[string]struct{})
	if m.policy != nil && m.policy.TransferPolicy != nil {
		for name := range m.policy.TransferPolicy.AssetSets {
			seen[name] = struct{}{}
		}
	}
	return uniqueNameWithSeen(base, "asset_set", seen)
}

func (m Model) assetSetRows() []assetSetRow {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return nil
	}
	return transferAssetSetRows(m.policy.TransferPolicy.AssetSets)
}

func (m Model) matchingAssetSetName(raw string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" || strings.HasPrefix(name, "@") {
		return "", false
	}
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return "", false
	}
	_, ok := m.policy.TransferPolicy.AssetSets[name]
	return name, ok
}

func (m Model) assetSetReferenceSummary() string {
	rows := m.assetSetRows()
	if len(rows) == 0 {
		return ""
	}
	limit := len(rows)
	if limit > 4 {
		limit = 4
	}
	names := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		names = append(names, rows[i].Name)
	}
	if len(rows) > limit {
		names = append(names, fmt.Sprintf("+%d more", len(rows)-limit))
	}
	return strings.Join(names, ", ")
}
