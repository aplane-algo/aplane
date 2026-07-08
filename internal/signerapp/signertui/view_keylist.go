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

	"github.com/aplane-algo/aplane/internal/keytypeux"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
)

// hexPattern matches hex strings starting with 0x followed by hex digits
var hexPattern = regexp.MustCompile(`0x[0-9a-fA-F]+`)

const (
	keyListHelpText = "g: Generate | i: Import | b: Backup | r: Restore | p: Policy | l: Lock | /: Filter | s: Settings | q: Quit"
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
	if keytypes.IsGuardedAccountKeyType(keyType) {
		return buildGuardedDetailsParameterLines(parameters)
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

func buildGuardedDetailsParameterLines(parameters map[string]string) []string {
	var lines []string
	if value, ok := parameters["Sentry"]; ok {
		lines = append(lines, formatParameterDisplayLines("Sentry", "", value)...)
		lines = append(lines, "")
	}

	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		if key == "Sentry" || key == keytypes.ParameterSentryPublicKey {
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
	tabKeys := filterKeysForTab(m.keylist.keys, m.effectiveKeyListTab())
	if m.keylist.filterInput == "" {
		return tabKeys
	}
	filter := strings.ToLower(m.keylist.filterInput)
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
	isSentry := keytypes.IsSentryComponentKeyType(key.KeyType)
	if tab == keyListTabSentry {
		return isSentry
	}
	return !isSentry
}

func (m Model) keyListMode() string {
	switch m.nodeRole() {
	case "sentry":
		return "sentry"
	default:
		return "signing"
	}
}

func (m Model) effectiveKeyListTab() keyListTab {
	switch m.keyListMode() {
	case "sentry":
		return keyListTabSentry
	default:
		return keyListTabSigning
	}
}

// syncKeyListTabWithMode resets the key-list selection when the node-role
// driven key view changes (e.g. admin settings arrive after startup).
func (m *Model) syncKeyListTabWithMode() {
	tab := m.effectiveKeyListTab()
	if m.keylist.tab == tab {
		return
	}
	m.keylist.tab = tab
	m.resetKeyListSelection()
}

func (m Model) activeKeyListTabLabel() string {
	if m.effectiveKeyListTab() == keyListTabSentry {
		return "Sentry"
	}
	return "Signing"
}

func (m Model) keyListFooterText() string {
	return keyListHelpText
}

// renderKeyListView renders the main key list screen
func (m Model) renderKeyListView() string {
	var sb strings.Builder

	// Filter input
	if m.keylist.filterActive {
		sb.WriteString(fmt.Sprintf("Filter: %s_\n", m.keylist.filterInput))
	} else if m.keylist.filterInput != "" {
		sb.WriteString(fmt.Sprintf("Filter: %s (/ to edit, Esc to clear)\n", m.keylist.filterInput))
	}
	sb.WriteString("\n")

	// Get filtered key list
	tabKeys := filterKeysForTab(m.keylist.keys, m.effectiveKeyListTab())
	displayKeys := m.filteredKeys()

	if len(m.keylist.keys) == 0 {
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
		sb.WriteString(fmt.Sprintf("\n  Total: %d keys\n", len(m.keylist.keys)))
	} else if len(displayKeys) == 0 {
		// Filter returned no matches
		sb.WriteString(subtitleStyle.Render("No keys match filter"))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("\n  Showing: 0 of %d %s keys\n", len(tabKeys), strings.ToLower(m.activeKeyListTabLabel())))
	} else {
		visibleHeight := m.keyListVisibleHeight()

		// Adjust scroll offset for filtered list
		scrollOffset := m.keylist.scrollOffset
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
			if i == m.keylist.selectedKey {
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

			if i == m.keylist.selectedKey {
				sb.WriteString(selectedStyle.Render(line))
			} else {
				sb.WriteString(normalStyle.Render(line))
			}
			sb.WriteString("\n")
		}

		sb.WriteString(scrollMoreBelowLine(len(displayKeys) - endIdx))
		sb.WriteString("\n")

		// Show filtered count vs total
		if m.keylist.filterInput != "" {
			sb.WriteString(fmt.Sprintf("\n  Showing: %d of %d %s keys\n", len(displayKeys), len(tabKeys), strings.ToLower(m.activeKeyListTabLabel())))
		} else {
			sb.WriteString(fmt.Sprintf("\n  Total: %d %s keys\n", len(tabKeys), strings.ToLower(m.activeKeyListTabLabel())))
		}
	}

	// If there's a pending signing request, show indicator
	if m.signing.request != nil {
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

	sb.WriteString(fmt.Sprintf("%s: %s", m.keyIdentifierLabel(m.details.keyType), m.details.address))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Type:    %s\n", styledKeyTypeWithTemplateProvenanceStatus(m.details.keyType, m.details.templateProvenanceStatus)))
	if m.details.publicKeyHex != "" {
		label := "Public key"
		if keytypes.IsSentryComponentKeyType(m.details.keyType) {
			label = "Sentry public key"
		}
		sb.WriteString(wrapText(fmt.Sprintf("%s: %s", label, displayPublicKeyHex(m.details.publicKeyHex)), m.popupBodyWidth(62)))
		sb.WriteString("\n")
	}
	if m.details.templateProvenanceNote != "" {
		sb.WriteString(warningStyle.Render("Template mismatch: " + m.details.templateProvenanceNote))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	maxVisibleLines := m.detailsVisibleLines()

	if len(m.details.parameters) > 0 {
		// Parameters view (for generic LogicSigs)
		sb.WriteString(keyTypeStyle.Render("═══ Parameters ═══"))
		sb.WriteString("\n\n")

		paramLines := buildDetailsParameterLines(m.details.keyType, m.details.parameters)
		totalParams := len(paramLines)
		needsScroll := totalParams > maxVisibleLines

		if needsScroll && m.details.scrollOffset > 0 {
			sb.WriteString(helpStyle.Render("  ▲ more above"))
			sb.WriteString("\n")
		}

		startIdx := m.details.scrollOffset
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
	if m.details.saveStatus != "" {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render(m.details.saveStatus))
		sb.WriteString("\n")
	}

	return m.renderPopup(62, sb.String())
}

func displayPublicKeyHex(publicKeyHex string) string {
	const maxPublicKeyPrefix = 20
	if len(publicKeyHex) <= maxPublicKeyPrefix {
		return publicKeyHex
	}
	return publicKeyHex[:maxPublicKeyPrefix] + "..."
}

func (m Model) renderTEALFullDisplay() string {
	width := m.width
	if width < 20 {
		width = 80
	}

	lines := strings.Split(m.details.teal, "\n")
	visibleLines := m.tealFullDisplayVisibleLines()
	offset := m.details.scrollOffset
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
	if m.details.address != "" {
		sb.WriteString(subtitleStyle.Render(ellipsize(m.details.address, width)))
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
	if m.details.address == "" {
		visible++
	}
	if visible < 3 {
		return 3
	}
	return visible
}
