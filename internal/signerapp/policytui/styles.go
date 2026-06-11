// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/theme"
)

var (
	titleStyle       lipgloss.Style
	subtitleStyle    lipgloss.Style
	panelStyle       lipgloss.Style
	sectionStyle     lipgloss.Style
	metadataStyle    lipgloss.Style
	statusOKStyle    lipgloss.Style
	statusWarnStyle  lipgloss.Style
	statusErrorStyle lipgloss.Style
	helpStyle        lipgloss.Style
	selectedStyle    lipgloss.Style
	descriptionStyle lipgloss.Style
	valueStyle       lipgloss.Style
	readonlyStyle    lipgloss.Style
	inputActiveStyle lipgloss.Style
	popupStyle       lipgloss.Style
)

func init() {
	initStyles()
}

func initStyles() {
	p := theme.Current()
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(p.Title))
	subtitleStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Subtitle))
	panelStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.InputBorder)).
		Padding(1, 2)
	sectionStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(p.Title))
	metadataStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Subtitle))
	statusOKStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusConnected)).
		Bold(true)
	statusWarnStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusLocked)).
		Bold(true)
	statusErrorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Error)).
		Bold(true)
	helpStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Help))
	selectedStyle = lipgloss.NewStyle().
		Background(lipgloss.Color(p.Selected)).
		Foreground(lipgloss.Color(p.SelectedFg)).
		Bold(true)
	descriptionStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Subtitle))
	valueStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusConnected))
	readonlyStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.InputInactive))
	inputActiveStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.InputActive)).
		Padding(0, 1)
	popupStyle = lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color(p.Popup)).
		Padding(1, 2)
}

func renderLines(lines ...string) string {
	return strings.Join(lines, "\n")
}
