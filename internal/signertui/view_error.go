// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
)

func (m Model) renderErrorView() string {
	title := strings.TrimSpace(m.errorPopup.title)
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
	sb.WriteString(wrapPlainText(message, bodyWidth))
	return m.renderPopup(92, sb.String())
}

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
		line := words[0]
		for _, word := range words[1:] {
			if len(line)+1+len(word) > width {
				out = append(out, line)
				line = word
				continue
			}
			line += " " + word
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
