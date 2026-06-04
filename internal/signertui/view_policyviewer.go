// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/policyview"
)

type policyViewerGuardField struct {
	key   string
	label string
	value string
	items []string
}

func (m Model) renderPolicyViewer() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Policy"))
	sb.WriteString("\n")
	sb.WriteString(subtitleStyle.Render("Read-only active signer policy"))
	sb.WriteString("\n\n")

	if m.policyViewListPopupField != "" {
		sb.WriteString(m.renderPolicyViewerListPopup())
		return m.constrainPolicyViewerBody(sb.String())
	}
	if m.policyLoadState != policyLoadIdle {
		sb.WriteString(m.renderPolicyLoadPanel())
		return m.constrainPolicyViewerBody(sb.String())
	}
	if m.policyViewLoading && !m.policyViewLoaded {
		sb.WriteString(subtitleStyle.Render("  Loading policy snapshot..."))
		return m.constrainPolicyViewerBody(sb.String())
	}
	if m.policyViewError != "" {
		sb.WriteString(errorStyle.Render(m.policyViewError))
		return m.constrainPolicyViewerBody(sb.String())
	}
	if !m.policyViewLoaded {
		sb.WriteString(subtitleStyle.Render("  No policy snapshot loaded"))
		return m.constrainPolicyViewerBody(sb.String())
	}

	sb.WriteString(m.renderPolicyViewerSnapshotSummary())
	if m.policyLoadStatus != "" {
		sb.WriteString("\n")
		sb.WriteString(statusConnectedStyle.Render(ellipsize(m.policyLoadStatus, m.policyViewerRowWidth())))
	}
	sb.WriteString("\n\n")
	sb.WriteString(m.renderPolicyViewerModeTabs())
	sb.WriteString("\n\n")
	switch m.policyViewMode {
	case policyViewerModeGuardDetail:
		sb.WriteString(m.renderPolicyViewerGuardDetail())
	case policyViewerModeYAML:
		sb.WriteString(m.renderPolicyViewerYAML())
	case policyViewerModeOverrides:
		sb.WriteString(m.renderPolicyViewerOverrides())
	default:
		sb.WriteString(m.renderPolicyViewerOverview())
	}

	return m.constrainPolicyViewerBody(sb.String())
}

func (m Model) renderPolicyViewerOverview() string {
	var sb strings.Builder
	sb.WriteString(m.renderPolicyViewerFieldSummary())
	sb.WriteString("\n\n")
	sb.WriteString(m.renderPolicyViewerGuardList())
	return sb.String()
}

func (m Model) renderPolicyViewerModeTabs() string {
	tabs := []struct {
		mode  policyViewerMode
		label string
	}{
		{policyViewerModeOverview, "1 Overview"},
		{policyViewerModeGuardDetail, "2 Guard"},
		{policyViewerModeYAML, "3 YAML"},
		{policyViewerModeOverrides, "4 Overrides"},
	}
	parts := make([]string, 0, len(tabs))
	for _, tab := range tabs {
		label := tab.label
		if m.policyViewMode == tab.mode {
			parts = append(parts, selectedStyle.Render(" "+label+" "))
		} else {
			parts = append(parts, subtitleStyle.Render(" "+label+" "))
		}
	}
	return lipgloss.NewStyle().MaxWidth(m.policyViewerRowWidth()).Render(strings.Join(parts, " "))
}

func (m Model) policyViewerHelp() string {
	if m.policyViewListPopupField != "" {
		return "up/down/pgup/pgdown: Scroll | Enter/Esc: Close"
	}
	switch m.policyViewMode {
	case policyViewerModeGuardDetail:
		return "left/right: Tabs | up/down: Field | enter: View list | l: Load YAML | r: Refresh | q: Back"
	case policyViewerModeYAML:
		return "left/right: Tabs | up/down/pgup/pgdown: Scroll | l: Load YAML | r: Refresh | q: Back"
	case policyViewerModeOverrides:
		return "left/right: Tabs | up/down: Select override | l: Load YAML | r: Refresh | q: Back"
	default:
		return "left/right: Tabs | up/down: Select guard | enter: Guard | l: Load YAML | r: Refresh | esc: Back"
	}
}

func (m Model) renderPolicyLoadPanel() string {
	var sb strings.Builder
	width := m.policyViewerRowWidth()
	sb.WriteString(subtitleStyle.Render("Load policy YAML"))
	sb.WriteString("\n")
	if m.policySnapshot != nil {
		sha := m.policySnapshot.PolicySHA256
		if sha == "" {
			sha = "-"
		}
		sb.WriteString(ellipsize("Current snapshot SHA-256: "+sha, width))
		sb.WriteString("\n")
	}
	if m.policyLoadError != "" {
		sb.WriteString(errorStyle.Render(ellipsize(m.policyLoadError, width)))
		sb.WriteString("\n")
	}

	switch m.policyLoadState {
	case policyLoadPath:
		displayPath := m.policyLoadPath
		if displayPath == "" {
			displayPath = " "
		} else {
			displayPath += "_"
		}
		sb.WriteString("\n")
		sb.WriteString("Path:\n")
		inputWidth := width - 2
		if inputWidth < 1 {
			inputWidth = 1
		}
		if inputWidth > 96 {
			inputWidth = 96
		}
		sb.WriteString(inputActiveStyle.Width(inputWidth).Render(displayPath))
	case policyLoadReading:
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Reading " + m.policyLoadPath + "..."))
	case policyLoadConfirm:
		sb.WriteString("\n")
		sb.WriteString(ellipsize("File: "+m.policyLoadPath, width))
		sb.WriteString("\n")
		sb.WriteString(ellipsize(fmt.Sprintf("Size: %d bytes", m.policyLoadBytes), width))
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render(ellipsize("This will replace policy.yaml as a whole file.", width)))
		sb.WriteString("\n\n")
		sb.WriteString(m.renderPolicyLoadPreview())
	case policyLoadReplacing:
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Replacing active policy..."))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) renderPolicyLoadPreview() string {
	yamlText := strings.TrimRight(m.policyLoadYAML, "\n")
	if yamlText == "" {
		return subtitleStyle.Render("  Policy YAML is empty")
	}
	lines := strings.Split(yamlText, "\n")
	limit := 8
	if len(lines) < limit {
		limit = len(lines)
	}
	width := m.policyViewerRowWidth()
	var sb strings.Builder
	sb.WriteString(subtitleStyle.Render("Preview"))
	sb.WriteString("\n")
	for i := 0; i < limit; i++ {
		sb.WriteString(ellipsize(fmt.Sprintf("%4d  %s", i+1, lines[i]), width))
		sb.WriteString("\n")
	}
	if len(lines) > limit {
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("  ... %d more lines", len(lines)-limit)))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) renderPolicyViewerSnapshotSummary() string {
	var sb strings.Builder
	width := m.policyViewerRowWidth()
	if m.policySnapshot != nil {
		identity := m.policySnapshot.IdentityID
		if identity == "" {
			identity = "-"
		}
		sha := m.policySnapshot.PolicySHA256
		if sha == "" {
			sha = "-"
		}
		sb.WriteString(ellipsize(fmt.Sprintf("Identity: %s", identity), width))
		sb.WriteString("\n")
		sb.WriteString(ellipsize(fmt.Sprintf("SHA-256: %s", sha), width))
	} else {
		sb.WriteString("Identity: -\nSHA-256: -")
	}
	return sb.String()
}

func (m Model) renderPolicyViewerFieldSummary() string {
	var sb strings.Builder
	sb.WriteString(subtitleStyle.Render("Policy defaults"))
	sb.WriteString("\n")
	width := m.policyViewerRowWidth()
	for _, field := range m.policyView.Fields {
		if field.Key == "transfer_policy" || field.Key == "key_overrides" {
			continue
		}
		line := fmt.Sprintf("  %-34s %-18s %s", field.Label, field.Value, field.Source)
		sb.WriteString(ellipsize(line, width))
		sb.WriteString("\n")
	}
	sb.WriteString(ellipsize(fmt.Sprintf(
		"  %-34s %-18s %s",
		"Transfer routing",
		m.policyView.TransferSummary,
		fmt.Sprintf("%d asset sets", len(m.policyView.AssetSets)),
	), width))
	sb.WriteString("\n")
	sb.WriteString(ellipsize(fmt.Sprintf(
		"  %-34s %-18d %s",
		"Key overrides",
		len(m.policyView.KeyOverrides),
		"read-only",
	), width))
	sb.WriteString("\n")
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) renderPolicyViewerGuardList() string {
	var sb strings.Builder
	groups := m.policyView.TransferGuards
	sb.WriteString(subtitleStyle.Render("Transfer guards"))
	sb.WriteString("\n")
	if len(groups) == 0 {
		sb.WriteString(subtitleStyle.Render("  No transfer guards configured"))
		sb.WriteString("\n")
		return sb.String()
	}

	displayModel := m.ensurePolicyViewGuardVisible()
	visible := displayModel.policyViewerVisibleGuardRows()
	offset := displayModel.policyViewGuardScrollOffset
	end := offset + visible
	if end > len(groups) {
		end = len(groups)
	}

	if above := scrollMoreAboveLine(offset); above != "" {
		sb.WriteString(above)
		sb.WriteString("\n")
	}
	for i := offset; i < end; i++ {
		group := groups[i]
		line := displayModel.policyViewerGuardLine(group, i == displayModel.policyViewSelectedGuard)
		if i == displayModel.policyViewSelectedGuard {
			sb.WriteString(selectedStyle.Render(line))
		} else if group.Advanced {
			sb.WriteString(warningStyle.Render(line))
		} else if group.Enabled != nil && !*group.Enabled {
			sb.WriteString(subtitleStyle.Render(line))
		} else {
			sb.WriteString(normalStyle.Render(line))
		}
		sb.WriteString("\n")
	}
	if below := scrollMoreBelowLine(len(groups) - end); below != "" {
		sb.WriteString(below)
		sb.WriteString("\n")
	}

	selected := displayModel.policyViewSelectedGuard
	if selected >= 0 && selected < len(groups) {
		sb.WriteString("\n")
		sb.WriteString(displayModel.renderPolicyViewerSelectedGuardDescription(groups[selected]))
		sb.WriteString("\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) renderPolicyViewerGuardDetail() string {
	groups := m.policyView.TransferGuards
	if len(groups) == 0 {
		return subtitleStyle.Render("  No transfer guards configured")
	}
	displayModel := m.ensurePolicyViewGuardVisible()
	selected := displayModel.policyViewSelectedGuard
	if selected < 0 || selected >= len(groups) {
		return subtitleStyle.Render("  No guard selected")
	}

	group := groups[selected]
	displayModel = displayModel.ensurePolicyViewGuardFieldVisible()
	var sb strings.Builder
	width := m.policyViewerRowWidth()
	sb.WriteString(subtitleStyle.Render(fmt.Sprintf("Guard %d of %d", selected+1, len(groups))))
	sb.WriteString("\n")
	sb.WriteString(displayModel.renderPolicyViewerSelectedGuard(group))
	sb.WriteString("\n")
	if len(group.RouteIndexes) > 0 {
		sb.WriteString(ellipsize("Route indexes: "+policyViewerIntListSummary(group.RouteIndexes), width))
		sb.WriteString("\n")
	}
	if len(group.AssetRows) > 0 {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Asset rules"))
		sb.WriteString("\n")
		for _, row := range group.AssetRows {
			line := fmt.Sprintf("  %-22s review above: %-12s reject above: %s",
				row.Asset,
				policyViewerAmountPtrLabel(row.ReviewAbove),
				policyViewerAmountPtrLabel(row.RejectAbove),
			)
			sb.WriteString(ellipsize(line, width))
			sb.WriteString("\n")
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) renderPolicyViewerYAML() string {
	yamlText := strings.TrimRight(m.policyView.YAML, "\n")
	if yamlText == "" {
		return subtitleStyle.Render("  Policy YAML is empty")
	}
	lines := strings.Split(yamlText, "\n")
	displayModel := m.ensurePolicyViewYAMLVisible()
	visible := displayModel.policyViewerYAMLVisibleLines()
	offset := displayModel.policyViewYAMLScrollOffset
	end := offset + visible
	if end > len(lines) {
		end = len(lines)
	}

	var sb strings.Builder
	if above := scrollMoreAboveLine(offset); above != "" {
		sb.WriteString(above)
		sb.WriteString("\n")
	}
	width := displayModel.policyViewerRowWidth()
	for i := offset; i < end; i++ {
		line := fmt.Sprintf("%4d  %s", i+1, lines[i])
		sb.WriteString(ellipsize(line, width))
		sb.WriteString("\n")
	}
	if below := scrollMoreBelowLine(len(lines) - end); below != "" {
		sb.WriteString(below)
		sb.WriteString("\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) renderPolicyViewerOverrides() string {
	overrides := m.policyView.KeyOverrides
	if len(overrides) == 0 {
		return subtitleStyle.Render("  No key overrides configured")
	}

	displayModel := m.ensurePolicyViewOverrideVisible()
	visible := displayModel.policyViewerOverrideVisibleRows()
	offset := displayModel.policyViewOverrideScrollOffset
	end := offset + visible
	if end > len(overrides) {
		end = len(overrides)
	}

	var sb strings.Builder
	sb.WriteString(subtitleStyle.Render("Key overrides"))
	sb.WriteString("\n")
	if above := scrollMoreAboveLine(offset); above != "" {
		sb.WriteString(above)
		sb.WriteString("\n")
	}
	width := displayModel.policyViewerRowWidth()
	for i := offset; i < end; i++ {
		key := overrides[i]
		prefix := "  "
		if i == displayModel.policyViewSelectedOverride {
			prefix = "> "
		}
		line := ellipsize(fmt.Sprintf("%s%-44s %s", prefix, displayPolicyOverrideKey(key), policyViewerOverrideSummary(displayModel, key)), width)
		if i == displayModel.policyViewSelectedOverride {
			sb.WriteString(selectedStyle.Render(line))
		} else {
			sb.WriteString(normalStyle.Render(line))
		}
		sb.WriteString("\n")
	}
	if below := scrollMoreBelowLine(len(overrides) - end); below != "" {
		sb.WriteString(below)
		sb.WriteString("\n")
	}

	selected := displayModel.policyViewSelectedOverride
	if selected >= 0 && selected < len(overrides) {
		sb.WriteString("\n")
		sb.WriteString(displayModel.renderPolicyViewerOverrideDetail(overrides[selected]))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) renderPolicyViewerOverrideDetail(key string) string {
	if m.policyView.Policy == nil || m.policyView.Policy.KeyOverrides == nil {
		return ""
	}
	override := m.policyView.Policy.KeyOverrides[key]
	if override == nil {
		return subtitleStyle.Render("  Empty override")
	}
	overrideView := policyview.Build(override, "")
	width := m.policyViewerRowWidth()
	var sb strings.Builder
	sb.WriteString(keyTypeStyle.Render(ellipsize(displayPolicyOverrideKey(key), width)))
	sb.WriteString("\n")
	lines := policyViewerExplicitOverrideLines(overrideView)
	if len(lines) == 0 {
		sb.WriteString(subtitleStyle.Render("  No explicit override fields"))
		return sb.String()
	}
	for _, line := range lines {
		sb.WriteString(ellipsize(line, width))
		sb.WriteString("\n")
	}
	if len(overrideView.TransferGuards) > 0 {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Override guards"))
		sb.WriteString("\n")
		for _, group := range overrideView.TransferGuards {
			sb.WriteString(ellipsize("  "+group.ID+"  assets: "+policyViewerAssetSummary(group), width))
			sb.WriteString("\n")
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) policyViewerGuardLine(group policyview.TransferGuardGroup, selected bool) string {
	prefix := "  "
	if selected {
		prefix = "> "
	}
	status := policyViewerEnabledLabel(group.Enabled)
	line := fmt.Sprintf("%s%-24s %-9s",
		prefix,
		ellipsize(group.ID, 24),
		status,
	)
	return ellipsize(line, m.policyViewerRowWidth())
}

func (m Model) renderPolicyViewerSelectedGuard(group policyview.TransferGuardGroup) string {
	var sb strings.Builder
	width := m.policyViewerRowWidth()
	sb.WriteString(keyTypeStyle.Render(ellipsize(group.ID, width)))
	sb.WriteString("\n")
	if group.Advanced {
		sb.WriteString(warningStyle.Render(ellipsize("Advanced route: "+group.AdvancedReason, width)))
		sb.WriteString("\n")
	}
	fields := m.policyViewerGuardFieldsForGroup(group)
	for i, field := range fields {
		prefix := "  "
		if i == m.policyViewSelectedGuardField {
			prefix = "> "
		}
		line := ellipsize(fmt.Sprintf("%s%-18s %s", prefix, field.label, field.value), width)
		if i == m.policyViewSelectedGuardField {
			sb.WriteString(selectedStyle.Render(line))
		} else {
			sb.WriteString(normalStyle.Render(line))
		}
		sb.WriteString("\n")
	}
	if len(group.AssetRows) > 0 {
		sb.WriteString(ellipsize("Assets: "+policyViewerAssetLimitSummary(group), width))
	} else {
		return strings.TrimRight(sb.String(), "\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (m Model) renderPolicyViewerSelectedGuardDescription(group policyview.TransferGuardGroup) string {
	description := strings.TrimSpace(group.Description)
	if description == "" {
		description = "-"
	}
	return ellipsize("Description: "+description, m.policyViewerRowWidth())
}

func (m Model) renderPolicyViewerListPopup() string {
	field := m.currentPolicyViewerListPopupField()
	title := field.label
	if title == "" {
		title = "Values"
	}
	items := field.items
	if len(items) == 0 {
		items = []string{"*"}
	}
	displayModel := m.ensurePolicyViewListPopupVisible()
	visible := displayModel.policyViewerListPopupVisibleLines()
	offset := displayModel.policyViewListPopupScroll
	end := offset + visible
	if end > len(items) {
		end = len(items)
	}

	bodyWidth := displayModel.popupBodyWidth(92)
	if bodyWidth < 1 {
		bodyWidth = displayModel.policyViewerRowWidth()
	}
	var body strings.Builder
	body.WriteString(titleStyle.Render(title))
	body.WriteString("\n")
	if above := scrollMoreAboveLine(offset); above != "" {
		body.WriteString(above)
		body.WriteString("\n")
	}
	for i := offset; i < end; i++ {
		body.WriteString(ellipsize(fmt.Sprintf("%3d  %s", i+1, items[i]), bodyWidth))
		body.WriteString("\n")
	}
	if below := scrollMoreBelowLine(len(items) - end); below != "" {
		body.WriteString(below)
		body.WriteString("\n")
	}
	return displayModel.renderPopup(96, strings.TrimRight(body.String(), "\n"))
}

func (m Model) policyViewerGuardFields() []policyViewerGuardField {
	groups := m.policyView.TransferGuards
	selected := m.policyViewSelectedGuard
	if selected < 0 || selected >= len(groups) {
		return nil
	}
	return m.policyViewerGuardFieldsForGroup(groups[selected])
}

func (m Model) policyViewerGuardFieldsForGroup(group policyview.TransferGuardGroup) []policyViewerGuardField {
	description := strings.TrimSpace(group.Description)
	if description == "" {
		description = "-"
	}
	return []policyViewerGuardField{
		{key: "description", label: "Description", value: description},
		{key: "enabled", label: "Enabled", value: policyViewerEnabledLabel(group.Enabled)},
		{key: "networks", label: "Networks", value: policyViewerReadOnlyListValue(group.Networks), items: append([]string(nil), group.Networks...)},
		{key: "sources", label: "Sources", value: policyViewerReadOnlyListValue(group.Sources), items: append([]string(nil), group.Sources...)},
		{key: "destinations", label: "Destinations", value: policyViewerReadOnlyListValue(group.Destinations), items: append([]string(nil), group.Destinations...)},
		{key: "close_allow", label: "Close remainder", value: policyViewerPermissionLabel(group.CloseAllow)},
	}
}

func (m Model) currentPolicyViewerGuardField() policyViewerGuardField {
	fields := m.policyViewerGuardFields()
	if len(fields) == 0 {
		return policyViewerGuardField{}
	}
	selected := m.policyViewSelectedGuardField
	if selected < 0 {
		selected = 0
	}
	if selected >= len(fields) {
		selected = len(fields) - 1
	}
	return fields[selected]
}

func (m Model) currentPolicyViewerListPopupField() policyViewerGuardField {
	for _, field := range m.policyViewerGuardFields() {
		if field.key == m.policyViewListPopupField {
			return field
		}
	}
	return policyViewerGuardField{}
}

func (m Model) policyViewerListPopupItems() []string {
	return append([]string(nil), m.currentPolicyViewerListPopupField().items...)
}

func (m Model) policyViewerListPopupVisibleLines() int {
	if m.height <= 0 {
		return 8
	}
	visible := m.popupContentHeight() - 4
	if visible < 3 {
		return 3
	}
	if visible > 12 {
		return 12
	}
	return visible
}

func (m Model) policyViewerVisibleGuardRows() int {
	if m.height <= 0 {
		return 10
	}
	visible := m.policyViewerContentHeight() - 22
	if visible < 1 {
		visible = 1
	}
	if visible > 10 {
		visible = 10
	}
	return visible
}

func (m Model) policyViewerYAMLVisibleLines() int {
	if m.height <= 0 {
		return 20
	}
	visible := m.policyViewerContentHeight() - 10
	if visible < 1 {
		visible = 1
	}
	return visible
}

func (m Model) policyViewerOverrideVisibleRows() int {
	if m.height <= 0 {
		return 10
	}
	visible := m.policyViewerContentHeight() - 17
	if visible < 1 {
		visible = 1
	}
	if visible > 10 {
		visible = 10
	}
	return visible
}

func (m Model) policyViewerRowWidth() int {
	if m.width <= 0 {
		return 96
	}
	if m.width > 4 {
		return m.width - 4
	}
	return 1
}

func (m Model) policyViewerContentHeight() int {
	height := m.windowBodyHeight()
	if height <= 0 {
		return 0
	}
	return height
}

func (m Model) constrainPolicyViewerBody(body string) string {
	style := lipgloss.NewStyle()
	if m.width > 0 {
		style = style.MaxWidth(m.width)
	}
	if height := m.policyViewerContentHeight(); height > 0 {
		style = style.MaxHeight(height)
	}
	return style.Render(strings.TrimRight(body, "\n"))
}

func policyViewerEnabledLabel(v *bool) string {
	if v == nil {
		return "default"
	}
	if *v {
		return "enabled"
	}
	return "disabled"
}

func policyViewerPermissionLabel(v *bool) string {
	if v == nil {
		return "default"
	}
	if *v {
		return "allow"
	}
	return "reject"
}

func policyViewerAssetSummary(group policyview.TransferGuardGroup) string {
	if group.Advanced {
		return "advanced"
	}
	assets := make([]string, 0, len(group.AssetRows))
	for _, row := range group.AssetRows {
		assets = append(assets, row.Asset)
	}
	return policyViewerListSummary(assets, 3)
}

func policyViewerAssetLimitSummary(group policyview.TransferGuardGroup) string {
	parts := make([]string, 0, len(group.AssetRows))
	for _, row := range group.AssetRows {
		part := row.Asset
		if row.ReviewAbove != nil {
			part += fmt.Sprintf(" review>%d", *row.ReviewAbove)
		}
		if row.RejectAbove != nil {
			part += fmt.Sprintf(" reject>%d", *row.RejectAbove)
		}
		parts = append(parts, part)
	}
	return policyViewerListSummary(parts, 3)
}

func policyViewerAmountPtrLabel(v *uint64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *v)
}

func policyViewerReadOnlyListValue(items []string) string {
	if len(items) == 0 {
		return "*"
	}
	if len(items) == 1 {
		return items[0]
	}
	return fmt.Sprintf("(%d)", len(items))
}

func policyViewerListSummary(items []string, maxItems int) string {
	if len(items) == 0 {
		return "*"
	}
	if len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	out := append([]string(nil), items[:maxItems]...)
	out = append(out, fmt.Sprintf("+%d", len(items)-maxItems))
	return strings.Join(out, ", ")
}

func policyViewerIntListSummary(items []int) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%d", item))
	}
	return policyViewerListSummary(parts, 8)
}

func displayPolicyOverrideKey(key string) string {
	return key
}

func policyViewerOverrideSummary(m Model, key string) string {
	if m.policyView.Policy == nil || m.policyView.Policy.KeyOverrides == nil {
		return "empty"
	}
	override := m.policyView.Policy.KeyOverrides[key]
	if override == nil {
		return "empty"
	}
	overrideView := policyview.Build(override, "")
	parts := make([]string, 0, 3)
	explicit := policyViewerExplicitOverrideLines(overrideView)
	if len(explicit) > 0 {
		parts = append(parts, fmt.Sprintf("%d fields", len(explicit)))
	}
	if override.TransferPolicy != nil {
		parts = append(parts, overrideView.TransferSummary)
	}
	if len(overrideView.TransferGuards) > 0 {
		parts = append(parts, fmt.Sprintf("%d guards", len(overrideView.TransferGuards)))
	}
	if len(parts) == 0 {
		return "empty"
	}
	return strings.Join(parts, " | ")
}

func policyViewerExplicitOverrideLines(view policyview.Model) []string {
	lines := make([]string, 0, len(view.Fields))
	for _, field := range view.Fields {
		switch field.Key {
		case "transfer_policy":
			if field.Source == "explicit" {
				lines = append(lines, fmt.Sprintf("  %-34s %s", field.Label, field.Value))
			}
		case "key_overrides":
			continue
		default:
			if field.Source == "explicit" {
				lines = append(lines, fmt.Sprintf("  %-34s %s", field.Label, field.Value))
			}
		}
	}
	if len(view.AssetSets) > 0 {
		lines = append(lines, fmt.Sprintf("  %-34s %d", "Asset sets", len(view.AssetSets)))
	}
	if len(view.BlockedDestinations) > 0 {
		lines = append(lines, fmt.Sprintf("  %-34s %d", "Blocked destinations", len(view.BlockedDestinations)))
	}
	return lines
}
