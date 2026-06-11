// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) renderLibraryTemplateDetails() string {
	width := m.width
	if width < 20 {
		width = 80
	}

	var sb strings.Builder
	sb.WriteString(titleStyle.Render(libraryDetailsTitle(m.library.detailsTemplateType, m.library.detailsKeyType)))
	sb.WriteString("\n")
	if publisher := keyTypePublisher(m.library.detailsKeyType); publisher != "" {
		sb.WriteString(subtitleStyle.Render("Publisher: " + publisher))
		sb.WriteString("\n")
	}
	if m.library.detailsSourcePath != "" {
		sb.WriteString(subtitleStyle.Render(ellipsize(m.library.detailsSourcePath, width)))
		sb.WriteString("\n")
	}
	if m.library.detailsSourceModTime > 0 {
		modified := time.Unix(m.library.detailsSourceModTime, 0).UTC().Format("2006-01-02 15:04:05 UTC")
		sb.WriteString(subtitleStyle.Render("Modified: " + modified))
		sb.WriteString("\n")
	}
	if m.library.detailsSourceSHA256 != "" {
		sb.WriteString(subtitleStyle.Render("SHA-256: " + ellipsize(m.library.detailsSourceSHA256, width-9)))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	switch {
	case m.library.detailsLoading:
		sb.WriteString(subtitleStyle.Render("Loading..."))
		return sb.String()
	case m.library.detailsError != "" && m.library.detailsContent == "":
		sb.WriteString(errorStyle.Render(m.library.detailsError))
		return sb.String()
	}

	lines := strings.Split(m.library.detailsContent, "\n")
	visibleLines := m.libraryTemplateDetailsVisibleLines()
	offset := m.library.detailsScrollOffset
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

	if offset > 0 {
		sb.WriteString(scrollMoreAboveLine(offset))
		sb.WriteString("\n")
	}
	for _, line := range lines[offset:end] {
		sb.WriteString(ellipsize(line, width))
		sb.WriteString("\n")
	}
	if end < len(lines) {
		sb.WriteString(scrollMoreBelowLine(len(lines) - end))
		sb.WriteString("\n")
	}

	return sb.String()
}

func libraryDetailsTitle(templateType, keyType string) string {
	if templateType == libraryTypeCompiledProvider {
		return fmt.Sprintf("Compiled provider: %s", displayKeyType(keyType))
	}
	return fmt.Sprintf("Library YAML: %s", displayKeyType(keyType))
}

func (m Model) libraryTemplateDetailsVisibleLines() int {
	if m.height <= 0 {
		return 20
	}
	visible := m.height - 7
	if visible < 3 {
		return 3
	}
	return visible
}

func (m Model) handleLibraryTemplateDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		returnView := m.library.detailsReturnView
		if returnView == 0 {
			returnView = ViewTemplateLibrary
		}
		m.viewState = returnView
		m.library.detailsContent = ""
		m.library.detailsError = ""
		m.library.detailsSourcePath = ""
		m.library.detailsSourceSHA256 = ""
		m.library.detailsSourceModTime = 0
		m.library.detailsKeyType = ""
		m.library.detailsTemplateType = ""
		m.library.detailsScrollOffset = 0
		m.library.detailsLoading = false
		m.library.detailsReturnView = 0
		return m, nil
	case "up", "k":
		if m.library.detailsScrollOffset > 0 {
			m.library.detailsScrollOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := len(strings.Split(m.library.detailsContent, "\n")) - m.libraryTemplateDetailsVisibleLines()
		if maxOffset < 0 {
			maxOffset = 0
		}
		if m.library.detailsScrollOffset < maxOffset {
			m.library.detailsScrollOffset++
		}
		return m, nil
	case "pgup":
		visible := m.libraryTemplateDetailsVisibleLines()
		m.library.detailsScrollOffset -= visible
		if m.library.detailsScrollOffset < 0 {
			m.library.detailsScrollOffset = 0
		}
		return m, nil
	case "pgdown":
		visible := m.libraryTemplateDetailsVisibleLines()
		maxOffset := len(strings.Split(m.library.detailsContent, "\n")) - visible
		if maxOffset < 0 {
			maxOffset = 0
		}
		m.library.detailsScrollOffset += visible
		if m.library.detailsScrollOffset > maxOffset {
			m.library.detailsScrollOffset = maxOffset
		}
		return m, nil
	}
	return m, nil
}
