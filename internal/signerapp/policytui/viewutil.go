// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

// Shared rendering utilities: popup sizing, scroll markers, text
// fitting, and small parse/join helpers.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/policy"
)

func (m Model) appChromeLines() int {
	// panelStyle adds one border line and one padding line at both top and bottom.
	const panelBorderAndPadding = 4
	// Header before screen content: title, subtitle, spacer, store, identity,
	// document, state, and spacer before the active screen.
	lines := 8 + panelBorderAndPadding
	if m.status != "" {
		lines++
	}
	if m.err != "" {
		lines++
	}
	if m.busy {
		lines++
	}
	return lines
}

func (m Model) panelWidth() int {
	if m.width > 0 {
		w := m.width - 6
		if w < 60 {
			return 60
		}
		return w
	}
	return 96
}

func (m Model) renderPopup(maxWidth int, body string) string {
	return popupStyle.Width(m.popupWidth(maxWidth)).Render(constrainPopupBody(body, m.popupContentHeight()))
}

func (m Model) popupWidth(max int) int {
	if m.width <= 0 {
		return max
	}
	w := m.panelWidth() - 6
	if w < 40 {
		return 40
	}
	if max > 0 && w > max {
		return max
	}
	return w
}

func (m Model) popupBodyWidth(max int) int {
	w := m.popupWidth(max) - popupStyle.GetHorizontalFrameSize()
	if w < 1 {
		return 1
	}
	return w
}

func (m Model) popupContentHeight() int {
	if m.height <= 0 {
		return 0
	}
	h := m.height - m.appChromeLines() - popupStyle.GetVerticalFrameSize()
	if h < 1 {
		return 1
	}
	return h
}

func (m Model) renderHelp(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "keys:") || strings.HasPrefix(line, modifiedProductionWarning) {
			lines[i] = helpStyle.Render(line)
		}
	}
	return strings.Join(lines, "\n")
}

func scrollMoreAboveLine(count int) string {
	return scrollMoreLine(count, "above")
}

func scrollMoreBelowLine(count int) string {
	return scrollMoreLine(count, "below")
}

func scrollMoreLine(count int, direction string) string {
	if count <= 0 {
		return ""
	}
	return descriptionStyle.Render(fmt.Sprintf("  %d more %s", count, direction))
}

func fixedWidthFieldLine(line string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(line)
	if len(runes) > width {
		return string(runes[:width])
	}
	if len(runes) < width {
		return line + strings.Repeat(" ", width-len(runes))
	}
	return line
}

func constrainPopupBody(body string, maxLines int) string {
	if maxLines <= 0 {
		return body
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:maxLines], "\n")
}

func ellipsize(s string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}

func statusStyle(m Model) lipgloss.Style {
	if m.err != "" {
		return statusErrorStyle
	}
	if m.modified() || m.busy {
		return statusWarnStyle
	}
	return statusOKStyle
}

func stateStyle(state string) lipgloss.Style {
	if state == "modified" {
		return statusWarnStyle
	}
	return statusOKStyle
}

func maxOffsetForLines(lines []string, visibleLines int) int {
	if visibleLines < 1 {
		visibleLines = 1
	}
	maxOffset := len(lines) - visibleLines
	if maxOffset < 0 {
		return 0
	}
	return maxOffset
}

func parseCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseOptionalBool(raw string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "default", "inherit", "-":
		return nil, nil
	case "true", "yes", "y", "1":
		v := true
		return &v, nil
	case "false", "no", "n", "0":
		v := false
		return &v, nil
	default:
		return nil, fmt.Errorf("expected default, true, or false")
	}
}

func parseRequiredBool(raw string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "y", "1":
		v := true
		return &v, nil
	case "false", "no", "n", "0":
		v := false
		return &v, nil
	default:
		return nil, fmt.Errorf("expected true or false")
	}
}

func uniqueNameWithSeen(base, fallback string, seen map[string]struct{}) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = fallback
	}
	if _, ok := seen[base]; !ok {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		if _, ok := seen[candidate]; !ok {
			return candidate
		}
	}
}

func boolValueWithDefault(v *bool, defaultValue bool) string {
	if v == nil {
		return fmt.Sprintf("%t", defaultValue)
	}
	return fmt.Sprintf("%t", *v)
}

func joinTerms(terms []string) string {
	if len(terms) == 0 {
		return "-"
	}
	return strings.Join(terms, ",")
}

func joinAssetTerms(terms []policy.StoredAssetTerm) string {
	if len(terms) == 0 {
		return "-"
	}
	raw := make([]string, 0, len(terms))
	for _, term := range terms {
		raw = append(raw, term.Raw)
	}
	return strings.Join(raw, ",")
}
