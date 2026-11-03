// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// MinWidth and MinHeight are the smallest window, in columns and rows, that
// apadmin lays out for. Every view is designed and tested to fit at this size
// without scrolling; below it apadmin shows only a "window too small" screen
// and ignores every key but ctrl+c, so no key reaches a screen the operator
// cannot see. apconsole sizes its split layout so the signer pane is never
// smaller than this.
const (
	MinWidth  = 80
	MinHeight = 24
)

// windowRows is the height of the window apadmin runs in. Standalone, the
// model keeps one row back from the terminal it was given.
func (m Model) windowRows() int {
	if m.standalone {
		return m.height + 1
	}
	return m.height
}

// belowMinSize reports whether the window is known and smaller than the
// floor. Before the first size message arrives the size is unknown, and the
// views render at their fallback widths. A model given both dimensions
// directly also counts as sized.
func (m Model) belowMinSize() bool {
	if !m.sizeKnown && (m.width <= 0 || m.height <= 0) {
		return false
	}
	return m.width < MinWidth || m.windowRows() < MinHeight
}

// renderTooSmall is the whole screen while the window is below the floor.
func (m Model) renderTooSmall() string {
	lines := []string{
		titleStyle.UnsetMargins().Render("Window too small"),
		"",
		fmt.Sprintf("apadmin needs at least %d×%d; this window is %d×%d.", MinWidth, MinHeight, m.width, m.windowRows()),
	}
	if m.standalone {
		lines = append(lines, "Enlarge the window to continue.")
	} else {
		lines = append(lines, "Enlarge the window, or press F4 to zoom this pane.")
	}
	if isApprovalView(m.viewState) && m.approvalPending(m.viewState) {
		lines = append(lines, "", errorStyle.Render("An approval request is waiting."))
	}
	lines = append(lines, "", helpStyle.Render("ctrl+c: Quit"))
	body := lipgloss.NewStyle().Width(max(m.width, 1)).Render(strings.Join(lines, "\n"))
	if rows, keep := strings.Split(body, "\n"), max(m.height, 1); len(rows) > keep {
		body = strings.Join(rows[:keep], "\n")
	}
	return body
}
