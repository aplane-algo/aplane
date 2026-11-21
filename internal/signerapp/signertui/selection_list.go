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
// selected one (selectionRows), so the selection and everything after the
// list stay on screen. Each row is one line; the header and footer end with
// the newlines they need. A window too small even for the header, one row and
// the footer falls back to the shared popup viewport.
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
	return header + selectionRows(rows, selected, available-fixed) + footer
}

// listWindow is fitSelectionList for a full-window screen: fixed lines around
// the list are already spoken for, and the list shows the lines around the
// selected one rather than pushing it or what follows out of the window.
func (m Model) listWindow(lines []string, selected, fixed int) string {
	height := m.windowBodyHeight()
	if height <= 0 {
		return joinRows(lines)
	}
	return selectionRows(lines, selected, height-fixed)
}

// selectionRows is as many of rows as room holds, around the selected one,
// between a "more above" and a "more below" line for the rows they hide. A
// list at its top or bottom shows a row in place of the line it does not
// need, and in a room of one or two rows the lines give way to the rows:
// the selection matters more than the count of hidden rows.
func selectionRows(rows []string, selected, room int) string {
	if room >= len(rows) {
		return joinRows(rows)
	}
	if room < 3 {
		start, end := selectionWindow(selected, len(rows), max(room, 1))
		return joinRows(rows[start:end])
	}
	const moreLines = 2
	start, end := selectionWindow(selected, len(rows), room-moreLines)
	if start == 0 {
		end++
	} else if end == len(rows) {
		start--
	}
	var sb strings.Builder
	if start > 0 {
		sb.WriteString(scrollMoreAboveLine(start) + "\n")
	}
	sb.WriteString(joinRows(rows[start:end]))
	if end < len(rows) {
		sb.WriteString(scrollMoreBelowLine(len(rows)-end) + "\n")
	}
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

// scrollToSelection is the first row a list of total rows, visible at a time,
// draws from: offset moved the least that shows selected, and held where the
// window is full when the list allows. A screen that draws from a kept offset
// passes it through here as it draws, since a status bar or a list that
// changed after the last key can leave fewer rows than the key scrolled for.
func scrollToSelection(offset, selected, total, visible int) int {
	visible = max(visible, 1)
	selected = min(max(selected, 0), max(total-1, 0))
	offset = max(min(offset, selected), selected-visible+1)
	return max(0, min(offset, total-visible))
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
