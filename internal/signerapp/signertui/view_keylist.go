// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Key list and key details view rendering.

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/keytypeux"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/witness"
)

// hexPattern matches hex strings starting with 0x followed by hex digits
var hexPattern = regexp.MustCompile(`0x[0-9a-fA-F]+`)

const (
	keyListHelpText         = "g: Generate | i: Import | e: Cosigners | c: Clients | b: Backups | p: Policies | l: Lock | /: Filter | s: Settings | q: Quit"
	cosignerKeyListHelpText = "g: Generate | i: Import | c: Clients | b: Backups | p: Policies | l: Lock | /: Filter | s: Settings | q: Quit"
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

// detailsCosignerParameter is where key details carry a cosigned account's
// cosigner, by its Witness Key ID. The plain hosts declare it; a composed
// template declares only the public key, which the details leave out.
const detailsCosignerParameter = "cosigner"

// buildDetailsParameterLines lists a key's parameters. The values are what the
// key was made with, typed by the operator or restored from an archive, and
// the labels are its template's, so both are escaped.
func buildDetailsParameterLines(keyType string, parameters map[string]string) []string {
	var lines []string
	if spec := getParamSpecForKeyType(keyType); spec != nil {
		declared := slices.ContainsFunc(spec.Params, func(def lsigprovider.ParameterDef) bool {
			return def.Name == detailsCosignerParameter
		})
		if id, ok := parameters[detailsCosignerParameter]; ok && !declared {
			lines = append(lines, "Cosigner: "+terminalSafe(id), "")
		}
		for _, paramDef := range spec.Params {
			if value, ok := parameters[paramDef.Name]; ok {
				lines = append(lines, formatParameterDisplayLines(paramDef.Label, paramDef.Type, value)...)
				lines = append(lines, "")
			}
		}
		return trimTrailingBlankLines(lines)
	}

	// Sorted, so the lines and the scroll count keep their order between draws.
	for _, key := range slices.Sorted(maps.Keys(parameters)) {
		lines = append(lines, terminalSafe(fmt.Sprintf("%s: %s", key, parameters[key])), "")
	}
	return trimTrailingBlankLines(lines)
}

func formatParameterDisplayLines(label, paramType, value string) []string {
	if label == "" {
		label = "Parameter"
	}
	label = terminalSafe(label)
	if paramType != "address[]" {
		return []string{fmt.Sprintf("%s: %s", label, terminalSafe(value))}
	}

	entries := splitAddressListValue(value)
	if len(entries) == 0 {
		return []string{fmt.Sprintf("%s: %s", label, terminalSafe(value))}
	}

	lines := make([]string, 0, len(entries)+1)
	lines = append(lines, label+":")
	for _, entry := range entries {
		lines = append(lines, "  "+terminalSafe(entry))
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
	tabKeys := m.roleKeys()
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

// roleKeys is the keys the list shows: a cosigner node's cosigner keys, or
// any other node's signing keys.
func (m Model) roleKeys() []KeyInfo {
	cosigner := m.isCosignerNode()
	result := make([]KeyInfo, 0, len(m.keylist.keys))
	for _, key := range m.keylist.keys {
		if witness.IsKeyType(key.KeyType) == cosigner {
			result = append(result, key)
		}
	}
	return result
}

// syncKeyListWithRole resets the key-list selection when the node role the
// list shows changes (e.g. admin settings arrive after startup).
func (m *Model) syncKeyListWithRole() {
	if m.keylist.cosignerKeys == m.isCosignerNode() {
		return
	}
	m.keylist.cosignerKeys = m.isCosignerNode()
	m.resetKeyListSelection()
}

// keyListNoun names the keys the list shows. It differs from nodeRoleNoun:
// a signer's keys are signing keys.
func (m Model) keyListNoun() string {
	if m.isCosignerNode() {
		return "cosigner"
	}
	return "signing"
}

func (m Model) keyListFooterText() string {
	if m.isCosignerNode() {
		return cosignerKeyListHelpText
	}
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
	tabKeys := m.roleKeys()
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
		sb.WriteString(subtitleStyle.Render(fmt.Sprintf("No %s keys found", m.keyListNoun())))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("\n  Total: %d keys\n", len(m.keylist.keys)))
	} else if len(displayKeys) == 0 {
		// Filter returned no matches
		sb.WriteString(subtitleStyle.Render("No keys match filter"))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("\n  Showing: 0 of %d %s keys\n", len(tabKeys), m.keyListNoun()))
	} else {
		m.writeKeyRows(&sb, displayKeys, tabKeys)
	}

	return sb.String()
}

// keyListScrollOffset is the first of count shown keys the list draws, kept
// so the selected key is in view.
func (m Model) keyListScrollOffset(count int) int {
	return scrollToSelection(m.keylist.scrollOffset, m.keylist.selectedKey, count, m.keyListVisibleHeight())
}

// writeKeyRows writes the visible part of the key list, the selected key
// marked, and under it how many keys are shown.
func (m Model) writeKeyRows(sb *strings.Builder, displayKeys, tabKeys []KeyInfo) {
	visibleHeight := m.keyListVisibleHeight()
	scrollOffset := m.keyListScrollOffset(len(displayKeys))

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
			formatKeyAddress(key.Address, key.KeyType, keyAddressWidth(m.width, prefix, keyTypeSuffix), true),
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
		sb.WriteString(fmt.Sprintf("\n  Showing: %d of %d %s keys\n", len(displayKeys), len(tabKeys), m.keyListNoun()))
	} else {
		sb.WriteString(fmt.Sprintf("\n  Total: %d %s keys\n", len(tabKeys), m.keyListNoun()))
	}
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

// keyDetailsPopupWidth is Key Details' popup width.
const keyDetailsPopupWidth = 62

// detailsParameterRows is the parameter lines as Key Details draws them: a
// line wider than the popup is wrapped into several rows, so the pager and
// its scroll keys count the rows on screen, not the lines.
func (m Model) detailsParameterRows() []string {
	width := m.popupBodyWidth(keyDetailsPopupWidth)
	var rows []string
	for _, line := range buildDetailsParameterLines(m.details.keyType, m.details.parameters) {
		rows = append(rows, strings.Split(strings.TrimSuffix(wrapText(line, width), "\n"), "\n")...)
	}
	return rows
}

// keyDetailsHeader is what Key Details draws above the parameters.
func (m Model) keyDetailsHeader() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Key Details"))
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("%s: %s", m.keyIdentifierLabel(m.details.keyType), m.details.address))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Type:    %s\n", styledKeyTypeWithTemplateProvenanceStatus(m.details.keyType, m.details.templateProvenanceStatus)))
	if m.details.policyLabel != "" {
		sb.WriteString(fmt.Sprintf("Policy:  %s\n", terminalSafe(m.details.policyLabel)))
	}
	if line := m.sourceTokensLine(); line != "" {
		sb.WriteString(wrapText(line, m.popupBodyWidth(keyDetailsPopupWidth)) + "\n")
	}
	if m.details.publicKeyHex != "" {
		label := "Public key"
		if witness.IsKeyType(m.details.keyType) {
			label = "Cosigner public key"
		}
		sb.WriteString(wrapText(fmt.Sprintf("%s: %s", label, displayPublicKeyHex(m.details.publicKeyHex)), m.popupBodyWidth(keyDetailsPopupWidth)))
		sb.WriteString("\n")
	}
	if m.details.templateProvenanceNote != "" {
		sb.WriteString(warningStyle.Render("Template mismatch: " + terminalSafe(m.details.templateProvenanceNote)))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	return sb.String()
}

// keyDetailsTrailer is what Key Details draws below the parameters.
func (m Model) keyDetailsTrailer() string {
	var sb strings.Builder
	if isNativeKeyType(m.details.keyType) {
		sb.WriteString("m: Show recovery phrase\n")
	}
	if len(m.sourceTokens.rows) > 0 {
		sb.WriteString("o: Source tokens\n")
	}
	// Show save status if present
	if m.details.saveStatus != "" {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render(terminalSafe(m.details.saveStatus)))
		sb.WriteString("\n")
	}
	return sb.String()
}

// detailsScrollOffset is the first parameter row Key Details shows: the
// stored offset, held within the rows there are. The rows depend on the
// width, so an offset scrolled at another width may be past the end.
func (m Model) detailsScrollOffset() int {
	return max(0, min(m.details.scrollOffset, len(m.detailsParameterRows())-m.detailsVisibleLines()))
}

// renderKeyDetails renders the key details modal.
func (m Model) renderKeyDetails() string {
	var sb strings.Builder
	sb.WriteString(m.keyDetailsHeader())

	maxVisibleLines := m.detailsVisibleLines()

	if len(m.details.parameters) > 0 {
		// Parameters view (for generic LogicSigs)
		sb.WriteString(keyTypeStyle.Render(strings.TrimSuffix(keyDetailsParametersHeading, "\n\n")))
		sb.WriteString("\n\n")

		paramLines := m.detailsParameterRows()
		totalParams := len(paramLines)
		needsScroll := totalParams > maxVisibleLines

		startIdx := m.detailsScrollOffset()
		if needsScroll && startIdx > 0 {
			sb.WriteString(helpStyle.Render("  ▲ more above"))
			sb.WriteString("\n")
		}

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

	sb.WriteString(m.keyDetailsTrailer())
	return m.renderPopup(keyDetailsPopupWidth, sb.String())
}

func displayPublicKeyHex(publicKeyHex string) string {
	const maxPublicKeyPrefix = 20
	if len(publicKeyHex) <= maxPublicKeyPrefix {
		return publicKeyHex
	}
	return publicKeyHex[:maxPublicKeyPrefix] + "..."
}

func (m Model) renderTEALFullDisplay() string {
	width := m.pagerWidth()

	var sb strings.Builder
	sb.WriteString(m.tealFullDisplayHeader(width))
	writePagerLines(&sb, m.tealLines(), m.details.scrollOffset, m.tealFullDisplayVisibleLines(), func(line string) string {
		// The program as its template wrote it, with every control and
		// format character, bidirectional ones included, shown as an escape.
		return ellipsize(truncateLongHex(terminalSafeLines(strings.TrimSuffix(line, "\r")), 80), width)
	})
	return sb.String()
}

// tealFullDisplayHeader is what the TEAL pager draws above the source.
func (m Model) tealFullDisplayHeader(width int) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("TEAL Source"))
	sb.WriteString("\n")
	if m.details.address != "" {
		sb.WriteString(subtitleStyle.Render(ellipsize(m.details.address, width)))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	return sb.String()
}

func (m Model) tealLines() []string { return strings.Split(m.details.teal, "\n") }

func (m Model) tealFullDisplayVisibleLines() int {
	return m.pagerVisibleLines(m.tealFullDisplayHeader(m.pagerWidth()), pagerScrollFooter)
}
