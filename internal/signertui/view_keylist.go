// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Key list and key details view rendering.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/keytypeux"
)

// hexPattern matches hex strings starting with 0x followed by hex digits
var hexPattern = regexp.MustCompile(`0x[0-9a-fA-F]+`)

const (
	keyListHelpText     = "g: Generate | i: Import | b: Backup | r: Restore | p: Policy | l: Lock | /: Filter | s: Settings | q: Quit"
	keyListDualHelpText = "tab/left/right: Switch tab | " + keyListHelpText
)

// truncateLongHex shortens hex values longer than maxLen characters
// Example: 0x1234567890abcdef... becomes 0x1234...cdef
func truncateLongHex(line string, maxLen int) string {
	return hexPattern.ReplaceAllStringFunc(line, func(match string) string {
		if len(match) <= maxLen {
			return match
		}
		// Keep 0x + first 8 hex chars + ... + last 8 hex chars
		// 0x (2) + 8 + ... (3) + 8 = 21 chars minimum
		prefix := match[:10] // 0x + 8 chars
		suffix := match[len(match)-8:]
		return prefix + "..." + suffix
	})
}

func buildDetailsParameterLines(keyType string, parameters map[string]string) []string {
	if keytypes.IsAttestedAccountKeyType(keyType) {
		return buildAttestedDetailsParameterLines(parameters)
	}

	var lines []string
	if spec := getParamSpecForKeyType(keyType); spec != nil {
		for _, paramDef := range spec.Params {
			if value, ok := parameters[paramDef.Name]; ok {
				lines = append(lines, formatParameterDisplayLines(paramDef.Label, paramDef.Type, value)...)
				lines = append(lines, "")
			}
		}
		return trimTrailingBlankLines(lines)
	}

	for key, value := range parameters {
		lines = append(lines, fmt.Sprintf("%s: %s", key, value), "")
	}
	return trimTrailingBlankLines(lines)
}

func buildAttestedDetailsParameterLines(parameters map[string]string) []string {
	var lines []string
	if value, ok := parameters["Attestor"]; ok {
		lines = append(lines, formatParameterDisplayLines("Attestor", "", value)...)
		lines = append(lines, "")
	}

	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		if key == "Attestor" || key == keytypes.ParameterAttestorPublicKey {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s: %s", key, parameters[key]), "")
	}
	return trimTrailingBlankLines(lines)
}

func formatParameterDisplayLines(label, paramType, value string) []string {
	if label == "" {
		label = "Parameter"
	}
	if paramType != "address[]" {
		return []string{fmt.Sprintf("%s: %s", label, value)}
	}

	entries := splitAddressListValue(value)
	if len(entries) == 0 {
		return []string{fmt.Sprintf("%s: %s", label, value)}
	}

	lines := make([]string, 0, len(entries)+1)
	lines = append(lines, label+":")
	for _, entry := range entries {
		lines = append(lines, "  "+entry)
	}
	return lines
}

func keyTypeDisplayWithTemplateProvenanceStatus(keyType, templateProvenanceStatus string) string {
	label := displayKeyType(keyType)
	if provenanceLabel := keytypeux.TemplateProvenanceLabel(templateProvenanceStatus); provenanceLabel != "" {
		return label + " [" + provenanceLabel + "]"
	}
	return label
}

func styledKeyTypeWithTemplateProvenanceStatus(keyType, templateProvenanceStatus string) string {
	styled := styledKeyType(keyType)
	if provenanceLabel := keytypeux.TemplateProvenanceLabel(templateProvenanceStatus); provenanceLabel != "" {
		return styled + " " + warningStyle.Render("["+provenanceLabel+"]")
	}
	return styled
}

func trimTrailingBlankLines(lines []string) []string {
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// filteredKeys returns keys matching the current filter
// Both address and key type match if they contain the filter anywhere
// matchesFilter checks if value matches the filter pattern.
// Supports ^ for prefix matching and $ for suffix matching.
func matchesFilter(value, filter string) bool {
	prefix := strings.HasPrefix(filter, "^")
	suffix := strings.HasSuffix(filter, "$")
	pattern := strings.TrimPrefix(strings.TrimSuffix(filter, "$"), "^")
	switch {
	case prefix && suffix:
		return value == pattern
	case prefix:
		return strings.HasPrefix(value, pattern)
	case suffix:
		return strings.HasSuffix(value, pattern)
	default:
		return strings.Contains(value, pattern)
	}
}

func (m Model) filteredKeys() []KeyInfo {
	tabKeys := filterKeysForTab(m.keys, m.effectiveKeyListTab())
	if m.filterInput == "" {
		return tabKeys
	}
	filter := strings.ToLower(m.filterInput)
	var result []KeyInfo
	for _, key := range tabKeys {
		if matchesFilter(strings.ToLower(key.Address), filter) ||
			matchesFilter(strings.ToLower(key.KeyType), filter) ||
			matchesFilter(strings.ToLower(keyTypeDisplayWithTemplateProvenanceStatus(key.KeyType, key.TemplateProvenanceStatus)), filter) {
			result = append(result, key)
		}
	}
	return result
}

func filterKeysForTab(keys []KeyInfo, tab keyListTab) []KeyInfo {
	result := make([]KeyInfo, 0, len(keys))
	for _, key := range keys {
		if keyBelongsToTab(key, tab) {
			result = append(result, key)
		}
	}
	return result
}

func keyBelongsToTab(key KeyInfo, tab keyListTab) bool {
	isAttestor := keytypes.IsAttestorComponentKeyType(key.KeyType)
	if tab == keyListTabAttestor {
		return isAttestor
	}
	return !isAttestor
}

func keyListTabForKey(key KeyInfo) keyListTab {
	if keytypes.IsAttestorComponentKeyType(key.KeyType) {
		return keyListTabAttestor
	}
	return keyListTabSigning
}

func (m Model) keyListMode() string {
	if m.adminSettings == nil {
		return "signing"
	}
	switch strings.ToLower(strings.TrimSpace(m.adminSettings.Mode)) {
	case "attestation":
		return "attestation"
	case "dual":
		return "dual"
	default:
		return "signing"
	}
}

func (m Model) keyListUsesTabs() bool {
	return m.keyListMode() == "dual"
}

func (m Model) effectiveKeyListTab() keyListTab {
	switch m.keyListMode() {
	case "attestation":
		return keyListTabAttestor
	case "dual":
		return m.keyListTab
	default:
		return keyListTabSigning
	}
}

func (m Model) keyListTabForMode(tab keyListTab) keyListTab {
	if m.keyListUsesTabs() {
		return tab
	}
	return m.effectiveKeyListTab()
}

func (m *Model) syncKeyListTabWithMode() {
	if m.keyListUsesTabs() {
		return
	}
	tab := m.effectiveKeyListTab()
	if m.keyListTab == tab {
		return
	}
	m.keyListTab = tab
	m.resetKeyListSelection()
}

func (m Model) keyListTabCounts() (signing, attestor int) {
	for _, key := range m.keys {
		if keytypes.IsAttestorComponentKeyType(key.KeyType) {
			attestor++
		} else {
			signing++
		}
	}
	return signing, attestor
}

func (m Model) renderKeyListTabs() string {
	signing, attestor := m.keyListTabCounts()
	labels := []struct {
		tab   keyListTab
		label string
		count int
	}{
		{tab: keyListTabSigning, label: "Signing", count: signing},
		{tab: keyListTabAttestor, label: "Attestor", count: attestor},
	}

	parts := make([]string, 0, len(labels))
	for _, item := range labels {
		text := fmt.Sprintf("%s (%d)", item.label, item.count)
		if m.effectiveKeyListTab() == item.tab {
			parts = append(parts, selectedStyle.Render("[ "+text+" ]"))
		} else {
			parts = append(parts, normalStyle.Render("  "+text+"  "))
		}
	}
	return strings.Join(parts, "  ")
}

func (m Model) activeKeyListTabLabel() string {
	if m.effectiveKeyListTab() == keyListTabAttestor {
		return "Attestor"
	}
	return "Signing"
}

func (m Model) keyListFooterText() string {
	if m.keyListUsesTabs() {
		return keyListDualHelpText
	}
	return keyListHelpText
}

// renderKeyListView renders the main key list screen
func (m Model) renderKeyListView() string {
	var sb strings.Builder

	if m.keyListUsesTabs() {
		sb.WriteString(m.renderKeyListTabs())
		sb.WriteString("\n")
	}

	// Filter input
	if m.filterActive {
		sb.WriteString(fmt.Sprintf("Filter: %s_\n", m.filterInput))
	} else if m.filterInput != "" {
		sb.WriteString(fmt.Sprintf("Filter: %s (/ to edit, Esc to clear)\n", m.filterInput))
	}
	sb.WriteString("\n")

	// Get filtered key list
	tabKeys := filterKeysForTab(m.keys, m.effectiveKeyListTab())
	displayKeys := m.filteredKeys()

	if len(m.keys) == 0 {
		if m.keyCount > 0 {
			sb.WriteString(fmt.Sprintf("✓ %d keys loaded in signer\n", m.keyCount))
			sb.WriteString(subtitleStyle.Render("Press 'r' to load key details"))
			sb.WriteString("\n")
		} else {
			sb.WriteString("No keys found. Press 'g' to generate a new key.\n")
		}
	} else if len(tabKeys) == 0 {
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("No %s keys found", strings.ToLower(m.activeKeyListTabLabel()))))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("\n  Total: %d keys\n", len(m.keys)))
	} else if len(displayKeys) == 0 {
		// Filter returned no matches
		sb.WriteString(subtitleStyle.Render("No keys match filter"))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("\n  Showing: 0 of %d %s keys\n", len(tabKeys), strings.ToLower(m.activeKeyListTabLabel())))
	} else {
		visibleHeight := m.keyListVisibleHeight()

		// Adjust scroll offset for filtered list
		scrollOffset := m.scrollOffset
		if scrollOffset >= len(displayKeys) {
			scrollOffset = 0
		}

		sb.WriteString(scrollMoreAboveLine(scrollOffset))
		sb.WriteString("\n")

		// Calculate end index
		endIdx := scrollOffset + visibleHeight
		if endIdx > len(displayKeys) {
			endIdx = len(displayKeys)
		}

		// Key list (only visible portion)
		for i := scrollOffset; i < endIdx; i++ {
			key := displayKeys[i]

			// Use cursor prefix for selection (more reliable than background colors)
			var prefix string
			if i == m.selectedKey {
				prefix = "> "
			} else {
				prefix = "  "
			}

			keyTypeText := keyTypeDisplayWithTemplateProvenanceStatus(key.KeyType, key.TemplateProvenanceStatus)
			keyTypeSuffix := "  " + keyTypeText
			line := fmt.Sprintf("%s%s  %s",
				prefix,
				formatKeyAddress(key.Address, key.KeyType, keyAddressWidth(m.width, prefix, "", keyTypeSuffix), true),
				styledKeyTypeWithTemplateProvenanceStatus(key.KeyType, key.TemplateProvenanceStatus),
			)

			if i == m.selectedKey {
				sb.WriteString(selectedStyle.Render(line))
			} else {
				sb.WriteString(normalStyle.Render(line))
			}
			sb.WriteString("\n")
		}

		sb.WriteString(scrollMoreBelowLine(len(displayKeys) - endIdx))
		sb.WriteString("\n")

		// Show filtered count vs total
		if m.filterInput != "" {
			sb.WriteString(fmt.Sprintf("\n  Showing: %d of %d %s keys\n", len(displayKeys), len(tabKeys), strings.ToLower(m.activeKeyListTabLabel())))
		} else {
			sb.WriteString(fmt.Sprintf("\n  Total: %d %s keys\n", len(tabKeys), strings.ToLower(m.activeKeyListTabLabel())))
		}
	}

	// If there's a pending signing request, show indicator
	if m.pendingSign != nil {
		sb.WriteString("\n")
		sb.WriteString(statusLockedStyle.Render("! Signing request pending - press any key to view"))
	}

	return sb.String()
}

func wrapShortcutHint(hint string, width int) string {
	if width <= 0 || lipgloss.Width(hint) <= width {
		return hint
	}
	parts := strings.Split(hint, " | ")
	lines := make([]string, 0, 2)
	line := ""
	for _, part := range parts {
		if line == "" {
			line = part
			continue
		}
		candidate := line + " | " + part
		if lipgloss.Width(candidate) <= width {
			line = candidate
			continue
		}
		lines = append(lines, line)
		line = part
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// renderKeyDetails renders the key details modal
func (m Model) renderKeyDetails() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Key Details"))
	sb.WriteString("\n")

	sb.WriteString(m.detailsAddress)
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Type:    %s\n", styledKeyTypeWithTemplateProvenanceStatus(m.detailsKeyType, m.detailsTemplateProvenanceStatus)))
	if m.detailsPublicKeyHex != "" {
		label := "Public key"
		if keytypes.IsAttestorComponentKeyType(m.detailsKeyType) {
			label = "Attestor public key"
		}
		sb.WriteString(wrapText(fmt.Sprintf("%s: %s", label, m.detailsPublicKeyHex), m.popupBodyWidth(62)))
		sb.WriteString("\n")
	}
	if m.detailsTemplateProvenanceNote != "" {
		sb.WriteString(warningStyle.Render("Template provenance: " + m.detailsTemplateProvenanceNote))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	maxVisibleLines := m.detailsVisibleLines()

	if len(m.detailsParameters) > 0 {
		// Parameters view (for generic LogicSigs)
		sb.WriteString(keyTypeStyle.Render("═══ Parameters ═══"))
		sb.WriteString("\n\n")

		paramLines := buildDetailsParameterLines(m.detailsKeyType, m.detailsParameters)
		totalParams := len(paramLines)
		needsScroll := totalParams > maxVisibleLines

		if needsScroll && m.detailsScrollOffset > 0 {
			sb.WriteString(helpStyle.Render("  ▲ more above"))
			sb.WriteString("\n")
		}

		startIdx := m.detailsScrollOffset
		endIdx := startIdx + maxVisibleLines
		if endIdx > totalParams {
			endIdx = totalParams
		}

		for i := startIdx; i < endIdx; i++ {
			sb.WriteString(paramLines[i])
			sb.WriteString("\n")
		}

		if needsScroll && endIdx < totalParams {
			sb.WriteString(helpStyle.Render("  ▼ more below"))
			sb.WriteString("\n")
		}
	}

	// Show save status if present
	if m.detailsSaveStatus != "" {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render(m.detailsSaveStatus))
		sb.WriteString("\n")
	}

	return m.renderPopup(62, sb.String())
}

func (m Model) renderTEALFullDisplay() string {
	width := m.width
	if width < 20 {
		width = 80
	}

	lines := strings.Split(m.detailsTEAL, "\n")
	visibleLines := m.tealFullDisplayVisibleLines()
	offset := m.detailsScrollOffset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(lines) {
		offset = 0
	}
	end := offset + visibleLines
	if end > len(lines) {
		end = len(lines)
	}

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("TEAL Source"))
	sb.WriteString("\n")
	if m.detailsAddress != "" {
		sb.WriteString(subtitleStyle.Render(ellipsize(m.detailsAddress, width)))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	if offset > 0 {
		sb.WriteString(scrollMoreAboveLine(offset))
		sb.WriteString("\n")
	}
	for _, line := range lines[offset:end] {
		sb.WriteString(ellipsize(truncateLongHex(line, 80), width))
		sb.WriteString("\n")
	}
	if end < len(lines) {
		sb.WriteString(scrollMoreBelowLine(len(lines) - end))
		sb.WriteString("\n")
	}

	return sb.String()
}

func (m Model) tealFullDisplayVisibleLines() int {
	if m.height <= 0 {
		return 20
	}
	visible := m.height - 7
	if m.detailsAddress == "" {
		visible++
	}
	if visible < 3 {
		return 3
	}
	return visible
}
