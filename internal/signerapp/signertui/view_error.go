// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

func (m Model) renderErrorView() string {
	title := terminalSafe(strings.TrimSpace(m.errorPopup.title))
	if title == "" {
		title = "Serious signer error"
	}
	message := strings.TrimSpace(m.errorPopup.message)
	if message == "" {
		message = "An unknown signer error occurred."
	}

	bodyWidth := m.popupBodyWidth(92)
	var sb strings.Builder
	sb.WriteString(errorStyle.Render(title))
	sb.WriteString("\n\n")
	sb.WriteString(wrapPlainText(terminalSafeLines(message), bodyWidth))
	return m.renderPopup(92, sb.String())
}

// wrapPlainText wraps each line of s at spaces to width columns, as the
// terminal draws them. A word wider than width is left whole on its own line.
func wrapPlainText(s string, width int) string {
	if width <= 0 {
		return s
	}
	var out []string
	for _, rawLine := range strings.Split(s, "\n") {
		words := strings.Fields(rawLine)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line, lineWidth := words[0], ansi.StringWidth(words[0])
		for _, word := range words[1:] {
			wordWidth := ansi.StringWidth(word)
			if lineWidth+1+wordWidth > width {
				out = append(out, line)
				line, lineWidth = word, wordWidth
				continue
			}
			line += " " + word
			lineWidth += 1 + wordWidth
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
