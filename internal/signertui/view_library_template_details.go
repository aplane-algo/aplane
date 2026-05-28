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
	sb.WriteString(titleStyle.Render(libraryDetailsTitle(m.libraryDetailsTemplateType, m.libraryDetailsKeyType)))
	sb.WriteString("\n")
	if publisher := keyTypePublisher(m.libraryDetailsKeyType); publisher != "" {
		sb.WriteString(subtitleStyle.Render("Publisher: " + publisher))
		sb.WriteString("\n")
	}
	if m.libraryDetailsSourcePath != "" {
		sb.WriteString(subtitleStyle.Render(ellipsize(m.libraryDetailsSourcePath, width)))
		sb.WriteString("\n")
	}
	if m.libraryDetailsSourceModTime > 0 {
		modified := time.Unix(m.libraryDetailsSourceModTime, 0).UTC().Format("2006-01-02 15:04:05 UTC")
		sb.WriteString(subtitleStyle.Render("Modified: " + modified))
		sb.WriteString("\n")
	}
	if m.libraryDetailsSourceSHA256 != "" {
		sb.WriteString(subtitleStyle.Render("SHA-256: " + ellipsize(m.libraryDetailsSourceSHA256, width-9)))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	switch {
	case m.libraryDetailsLoading:
		sb.WriteString(subtitleStyle.Render("Loading..."))
		return sb.String()
	case m.libraryDetailsError != "" && m.libraryDetailsContent == "":
		sb.WriteString(errorStyle.Render(m.libraryDetailsError))
		return sb.String()
	}

	lines := strings.Split(m.libraryDetailsContent, "\n")
	visibleLines := m.libraryTemplateDetailsVisibleLines()
	offset := m.libraryDetailsScrollOffset
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
		returnView := m.libraryDetailsReturnView
		if returnView == 0 {
			returnView = ViewTemplateLibrary
		}
		m.viewState = returnView
		m.libraryDetailsContent = ""
		m.libraryDetailsError = ""
		m.libraryDetailsSourcePath = ""
		m.libraryDetailsSourceSHA256 = ""
		m.libraryDetailsSourceModTime = 0
		m.libraryDetailsKeyType = ""
		m.libraryDetailsTemplateType = ""
		m.libraryDetailsScrollOffset = 0
		m.libraryDetailsLoading = false
		m.libraryDetailsReturnView = 0
		return m, nil
	case "up", "k":
		if m.libraryDetailsScrollOffset > 0 {
			m.libraryDetailsScrollOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := len(strings.Split(m.libraryDetailsContent, "\n")) - m.libraryTemplateDetailsVisibleLines()
		if maxOffset < 0 {
			maxOffset = 0
		}
		if m.libraryDetailsScrollOffset < maxOffset {
			m.libraryDetailsScrollOffset++
		}
		return m, nil
	case "pgup":
		visible := m.libraryTemplateDetailsVisibleLines()
		m.libraryDetailsScrollOffset -= visible
		if m.libraryDetailsScrollOffset < 0 {
			m.libraryDetailsScrollOffset = 0
		}
		return m, nil
	case "pgdown":
		visible := m.libraryTemplateDetailsVisibleLines()
		maxOffset := len(strings.Split(m.libraryDetailsContent, "\n")) - visible
		if maxOffset < 0 {
			maxOffset = 0
		}
		m.libraryDetailsScrollOffset += visible
		if m.libraryDetailsScrollOffset > maxOffset {
			m.libraryDetailsScrollOffset = maxOffset
		}
		return m, nil
	}
	return m, nil
}
