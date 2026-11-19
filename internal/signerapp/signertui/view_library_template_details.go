// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// libraryTemplateDetailsHeader is what the YAML pager draws above the file.
func (m Model) libraryTemplateDetailsHeader(width int) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(libraryDetailsTitle(m.library.detailsTemplateType, m.library.detailsKeyType, m.library.detailsInstalled)))
	sb.WriteString("\n")
	if publisher := keyTypePublisher(m.library.detailsKeyType); publisher != "" {
		sb.WriteString(subtitleStyle.Render("Publisher: " + publisher))
		sb.WriteString("\n")
	}
	if m.library.detailsSourcePath != "" {
		sb.WriteString(subtitleStyle.Render(ellipsize(terminalSafe(m.library.detailsSourcePath), width)))
		sb.WriteString("\n")
	}
	if m.library.detailsSourceModTime > 0 {
		modified := time.Unix(m.library.detailsSourceModTime, 0).UTC().Format("2006-01-02 15:04:05 UTC")
		sb.WriteString(subtitleStyle.Render("Modified: " + modified))
		sb.WriteString("\n")
	}
	if m.library.detailsSourceSHA256 != "" {
		sb.WriteString(subtitleStyle.Render("SHA-256: " + ellipsize(terminalSafe(m.library.detailsSourceSHA256), width-9)))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	return sb.String()
}

func (m Model) renderLibraryTemplateDetails() string {
	width := m.pagerWidth()
	var sb strings.Builder
	sb.WriteString(m.libraryTemplateDetailsHeader(width))

	switch {
	case m.library.detailsLoading:
		sb.WriteString(subtitleStyle.Render("Loading..."))
		return sb.String()
	case m.library.detailsError != "" && m.library.detailsContent == "":
		sb.WriteString(errorStyle.Render(terminalSafeLines(m.library.detailsError)))
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
		// The file is shown as written, but every control and format
		// character in it, bidirectional ones included, shows as an escape.
		// A CRLF file's line ends are line ends.
		sb.WriteString(ellipsize(terminalSafeLines(strings.TrimSuffix(line, "\r")), width))
		sb.WriteString("\n")
	}
	if end < len(lines) {
		sb.WriteString(scrollMoreBelowLine(len(lines) - end))
		sb.WriteString("\n")
	}

	return sb.String()
}

func libraryDetailsTitle(templateType, keyType string, installed bool) string {
	if templateType == libraryTypeCompiledProvider {
		return fmt.Sprintf("Compiled provider: %s", displayKeyType(keyType))
	}
	if installed {
		return fmt.Sprintf("Installed YAML: %s", displayKeyType(keyType))
	}
	return fmt.Sprintf("Library YAML: %s", displayKeyType(keyType))
}

func (m Model) libraryTemplateDetailsVisibleLines() int {
	return m.pagerVisibleLines(m.libraryTemplateDetailsHeader(m.pagerWidth()))
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
		m.library.detailsRequestID = ""
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
