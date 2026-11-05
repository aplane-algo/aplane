// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// fitSelectionList joins header, the selection list rows, and footer into a
// popup body that fits the window. When everything fits, every row is shown.
// Otherwise the header and footer stay whole (they carry the description of
// the selection and any buttons) and the list shows only the rows around the
// selected one, between "more above" and "more below" lines, so the selection
// and everything after the list stay on screen. When only one or two rows fit,
// the "more" lines are dropped so the footer still fits. Each row is one line;
// the header and footer end with the newlines they need. A window too small
// even for the header, one row and the footer falls back to the shared popup
// viewport.
func (m Model) fitSelectionList(header string, rows []string, selected int, footer string, popupWidth int) string {
	full := header + joinRows(rows) + footer
	available := m.popupContentHeight()
	if available <= 0 || len(rows) == 0 {
		return full
	}
	width := m.popupBodyWidth(popupWidth)
	if wrappedHeight(full, width) <= available {
		return full
	}
	// One stand-in row measures the lines the header and footer take.
	fixed := wrappedHeight(header+"x\n"+footer, width) - 1
	room := available - fixed
	if room >= 1 && room < 3 {
		// No space for the "more" lines as well as a row: the selection and
		// the footer matter more than the count of hidden rows.
		start, end := selectionWindow(selected, len(rows), room)
		return header + joinRows(rows[start:end]) + footer
	}
	visible := max(room-2, 1)
	if visible >= len(rows) {
		return full
	}
	start, end := selectionWindow(selected, len(rows), visible)
	// At either end of the list, the line kept for "more" there shows a row
	// instead.
	if start == 0 {
		end = min(end+1, len(rows))
	} else if end == len(rows) {
		start--
	}
	var sb strings.Builder
	sb.WriteString(header)
	if start > 0 {
		sb.WriteString(scrollMoreAboveLine(start))
		sb.WriteString("\n")
	}
	sb.WriteString(joinRows(rows[start:end]))
	if end < len(rows) {
		sb.WriteString(scrollMoreBelowLine(len(rows) - end))
		sb.WriteString("\n")
	}
	sb.WriteString(footer)
	return sb.String()
}

// listWindow is fitSelectionList for a full-window screen: fixed lines around
// the list are already spoken for, and the list shows the lines around the
// selected one rather than pushing it or what follows out of the window.
func (m Model) listWindow(lines []string, selected, fixed int) string {
	height := m.windowBodyHeight()
	if height <= 0 || fixed+len(lines) <= height {
		return joinRows(lines)
	}
	const moreLines = 2
	start, end := selectionWindow(selected, len(lines), max(height-fixed-moreLines, 1))
	var sb strings.Builder
	sb.WriteString(scrollMoreAboveLine(start) + "\n")
	sb.WriteString(joinRows(lines[start:end]))
	sb.WriteString(scrollMoreBelowLine(len(lines)-end) + "\n")
	return sb.String()
}

// selectionWindow is the run of visible rows out of total that keeps
// selected in view, centred where the list allows.
func selectionWindow(selected, total, visible int) (start, end int) {
	if visible >= total {
		return 0, total
	}
	selected = min(max(selected, 0), total-1)
	start = min(max(selected-visible/2, 0), total-visible)
	return start, start + visible
}

func joinRows(rows []string) string {
	var sb strings.Builder
	for _, row := range rows {
		sb.WriteString(row)
		sb.WriteString("\n")
	}
	return sb.String()
}

// wrappedHeight is how many lines body takes on screen in a popup body width
// columns wide, long lines wrapped as the popup style wraps them.
func wrappedHeight(body string, width int) int {
	body = strings.TrimRight(body, "\n")
	if body == "" {
		return 0
	}
	return lipgloss.Height(lipgloss.NewStyle().Width(width).Render(body))
}
