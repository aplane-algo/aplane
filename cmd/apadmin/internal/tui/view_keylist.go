// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

// Key list and key details view rendering.

import (
	"fmt"
	"regexp"
	"strings"
)

// hexPattern matches hex strings starting with 0x followed by hex digits
var hexPattern = regexp.MustCompile(`0x[0-9a-fA-F]+`)

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

// filteredKeys returns keys matching the current filter
// Both address and key type match if they contain the filter anywhere
func (m Model) filteredKeys() []KeyInfo {
	if m.filterInput == "" {
		return m.keys
	}
	filter := strings.ToLower(m.filterInput)
	var result []KeyInfo
	for _, key := range m.keys {
		if strings.Contains(strings.ToLower(key.Address), filter) ||
			strings.Contains(strings.ToLower(key.KeyType), filter) {
			result = append(result, key)
		}
	}
	return result
}

// renderKeyListView renders the main key list screen
func (m Model) renderKeyListView() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Signer Admin"))
	sb.WriteString("\n")

	// Filter input
	if m.filterActive {
		sb.WriteString(fmt.Sprintf("Filter: %s_\n", m.filterInput))
		sb.WriteString(helpStyle.Render("Enter: Apply | Esc: Clear"))
		sb.WriteString("\n")
	} else if m.filterInput != "" {
		sb.WriteString(fmt.Sprintf("Filter: %s (/ to edit, Esc to clear)\n", m.filterInput))
	}
	sb.WriteString("\n")

	// Get filtered key list
	displayKeys := m.filteredKeys()

	if len(m.keys) == 0 {
		if m.keyCount > 0 {
			sb.WriteString(fmt.Sprintf("✓ %d keys loaded in signer\n", m.keyCount))
			sb.WriteString(subtitleStyle.Render("Press 'r' to load key details"))
			sb.WriteString("\n")
		} else {
			sb.WriteString("No keys found. Press 'g' to generate a new key.\n")
		}
	} else if len(displayKeys) == 0 {
		// Filter returned no matches
		sb.WriteString(subtitleStyle.Render("No keys match filter"))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("\n  Total: %d keys\n", len(m.keys)))
	} else {
		// Calculate visible height for key list
		// Header: 4 lines (with filter), Footer: ~6 lines (total, help, possible pending indicator)
		// Reserve 2 lines for scroll indicators
		visibleHeight := m.height - 12
		if visibleHeight < 3 {
			visibleHeight = 3
		}

		// Adjust scroll offset for filtered list
		scrollOffset := m.scrollOffset
		if scrollOffset >= len(displayKeys) {
			scrollOffset = 0
		}

		// Show scroll-up indicator if not at top
		if scrollOffset > 0 {
			sb.WriteString(subtitleStyle.Render(fmt.Sprintf("  ▲ %d more above", scrollOffset)))
			sb.WriteString("\n")
		}

		// Calculate end index
		endIdx := scrollOffset + visibleHeight
		if endIdx > len(displayKeys) {
			endIdx = len(displayKeys)
		}

		// Key list (only visible portion)
		for i := scrollOffset; i < endIdx; i++ {
			key := displayKeys[i]
			displayAddr := key.Address

			// Use cursor prefix for selection (more reliable than background colors)
			var prefix string
			if i == m.selectedKey {
				prefix = "> "
			} else {
				prefix = "  "
			}

			line := fmt.Sprintf("%s%s  %s", prefix, displayAddr, styledKeyType(key.KeyType))

			if i == m.selectedKey {
				sb.WriteString(selectedStyle.Render(line))
			} else {
				sb.WriteString(normalStyle.Render(line))
			}
			sb.WriteString("\n")
		}

		// Show scroll-down indicator if more below
		if endIdx < len(displayKeys) {
			sb.WriteString(subtitleStyle.Render(fmt.Sprintf("  ▼ %d more below", len(displayKeys)-endIdx)))
			sb.WriteString("\n")
		}

		// Show filtered count vs total
		if m.filterInput != "" {
			sb.WriteString(fmt.Sprintf("\n  Showing: %d of %d keys\n", len(displayKeys), len(m.keys)))
		} else {
			sb.WriteString(fmt.Sprintf("\n  Total: %d keys\n", len(m.keys)))
		}
	}

	sb.WriteString("\n")
	if !m.filterActive {
		sb.WriteString(helpStyle.Render("/: Filter | g: Generate | i: Import | e: Export | d: Delete | r: Refresh | q: Quit"))
	}

	// If there's a pending signing request, show indicator
	if m.pendingSign != nil {
		sb.WriteString("\n\n")
		sb.WriteString(statusLockedStyle.Render("! Signing request pending - press any key to view"))
	}

	return sb.String()
}

// renderKeyDetails renders the key details modal
func (m Model) renderKeyDetails() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Key Details"))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n", m.detailsAddress))
	sb.WriteString(fmt.Sprintf("Type:    %s\n", styledKeyType(m.detailsKeyType)))
	sb.WriteString("\n")

	// Calculate visible lines (reserve space for header/footer)
	maxVisibleLines := 8
	if m.height > 30 {
		maxVisibleLines = 12
	} else if m.height < 20 {
		maxVisibleLines = 5
	}

	// Check if TEAL source is available (generic LogicSigs or DSA LogicSigs)
	hasTEAL := m.detailsTEAL != ""

	// Toggle between TEAL view and Info view
	if m.detailsShowTEAL && hasTEAL {
		// TEAL view
		sb.WriteString(keyTypeStyle.Render("═══ TEAL Source ═══"))
		sb.WriteString("\n\n")

		if m.detailsTEAL == "" {
			sb.WriteString(subtitleStyle.Render("TEAL source unavailable"))
			sb.WriteString("\n\n")
		} else {
			tealLines := strings.Split(m.detailsTEAL, "\n")
			totalLines := len(tealLines)
			needsScroll := totalLines > maxVisibleLines

			// Show scroll up indicator
			if needsScroll && m.detailsScrollOffset > 0 {
				sb.WriteString(helpStyle.Render("  ▲ more above"))
				sb.WriteString("\n")
			}

			// Display visible lines
			startIdx := m.detailsScrollOffset
			endIdx := startIdx + maxVisibleLines
			if endIdx > totalLines {
				endIdx = totalLines
			}

			for i := startIdx; i < endIdx; i++ {
				// Truncate long hex values (e.g., >1KB keys) for display
				sb.WriteString(truncateLongHex(tealLines[i], 40))
				sb.WriteString("\n")
			}

			// Show scroll down indicator
			if needsScroll && endIdx < totalLines {
				sb.WriteString(helpStyle.Render("  ▼ more below"))
				sb.WriteString("\n")
			}
		}
		sb.WriteString("\n")
	} else if len(m.detailsParameters) > 0 {
		// Parameters view (for generic LogicSigs)
		sb.WriteString(keyTypeStyle.Render("═══ Parameters ═══"))
		sb.WriteString("\n\n")

		// Get ordered parameter list
		var paramLines []string
		if spec := getParamSpecForKeyType(m.detailsKeyType); spec != nil {
			for _, paramDef := range spec.Params {
				if value, ok := m.detailsParameters[paramDef.Name]; ok {
					paramLines = append(paramLines, fmt.Sprintf("%s: %s", paramDef.Label, value))
				}
			}
		} else {
			for key, value := range m.detailsParameters {
				paramLines = append(paramLines, fmt.Sprintf("%s: %s", key, value))
			}
		}

		// Each param takes 2 lines (value + gap), so show half as many
		maxVisibleParams := maxVisibleLines / 2
		if maxVisibleParams < 3 {
			maxVisibleParams = 3
		}

		totalParams := len(paramLines)
		needsScroll := totalParams > maxVisibleParams

		if needsScroll && m.detailsScrollOffset > 0 {
			sb.WriteString(helpStyle.Render("  ▲ more above"))
			sb.WriteString("\n")
		}

		startIdx := m.detailsScrollOffset
		endIdx := startIdx + maxVisibleParams
		if endIdx > totalParams {
			endIdx = totalParams
		}

		for i := startIdx; i < endIdx; i++ {
			sb.WriteString(paramLines[i])
			sb.WriteString("\n\n") // Extra line for visual separation
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

	// Build help text based on available features
	var helpParts []string
	if hasTEAL {
		if m.detailsShowTEAL {
			helpParts = append(helpParts, "t=info")
		} else {
			helpParts = append(helpParts, "t=TEAL")
		}
		// Only show view/save if TEAL source is available
		if m.detailsTEAL != "" {
			helpParts = append(helpParts, "v=view", "s=save")
		}
	}
	if len(m.detailsParameters) > 0 || m.detailsTEAL != "" {
		helpParts = append(helpParts, "↑/↓ scroll")
	}
	helpParts = append(helpParts, "Enter/Esc close")
	sb.WriteString(helpStyle.Render(strings.Join(helpParts, " • ")))

	return popupStyle.Width(80).Render(sb.String())
}
