// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

// Core view rendering and styles.
// View-specific renderers are in view_*.go files.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/algorithm"
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	statusConnectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("42"))

	statusDisconnectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196"))

	statusLockedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("214"))

	statusUnlockedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("42"))

	inputStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(0, 1)

	inputActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("42")). // Green border when active
				Padding(0, 1)

	inputInactiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("241")). // Gray border when inactive
				Padding(0, 1)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)

	// warningStyle for policy warnings (orange/yellow)
	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)

	// criticalStyle for critical policy violations (red background)
	criticalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("255")).
			Background(lipgloss.Color("196")).
			Bold(true).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("62")).
			Foreground(lipgloss.Color("255")).
			Bold(true)

	normalStyle = lipgloss.NewStyle()

	buttonStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Border(lipgloss.RoundedBorder())

	buttonActiveStyle = buttonStyle.
				BorderForeground(lipgloss.Color("42")).
				Foreground(lipgloss.Color("42"))

	buttonInactiveStyle = buttonStyle.
				BorderForeground(lipgloss.Color("241")).
				Foreground(lipgloss.Color("241"))

	popupStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("214")).
			Padding(1, 2).
			Width(80)

	keyTypeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39"))
)

// styledKeyType returns a key type string styled with the algorithm's display color
// Uses raw ANSI codes for consistent behavior with apshell
func styledKeyType(keyType string) string {
	color := algorithm.GetDisplayColor(keyType)
	if color == "" {
		color = "39" // Default cyan if no color defined
	}
	// Use raw ANSI escape codes for consistent color rendering
	return fmt.Sprintf("\033[%sm[%s]\033[0m", color, keyType)
}

// View renders the TUI
func (m Model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	var content string

	switch m.viewState {
	case ViewAuth:
		content = m.renderAuthView()
	case ViewUnlock:
		content = m.renderUnlockView()
	case ViewKeyList:
		content = m.renderKeyListView()
	case ViewKeyDetails:
		content = m.renderKeyDetails()
	case ViewSigningPopup:
		content = m.renderSigningPopup()
	case ViewTokenProvisioningPopup:
		content = m.renderTokenProvisioningPopup()
	case ViewExportConfirm:
		content = m.renderExportConfirm()
	case ViewExportDisplay:
		content = m.renderExportDisplay()
	case ViewImportForm:
		content = m.renderImportForm()
	case ViewImportParams:
		content = m.renderImportParams()
	case ViewImporting:
		content = m.renderImporting()
	case ViewImportDisplay:
		content = m.renderImportDisplay()
	case ViewGenerateForm:
		content = m.renderGenerateForm()
	case ViewGenerateParams:
		content = m.renderGenerateParams()
	case ViewGenerating:
		content = m.renderGenerating()
	case ViewGenerateDisplay:
		content = m.renderGenerateDisplay()
	case ViewDeleteConfirm:
		content = m.renderDeleteConfirm()
	case ViewDeleting:
		content = m.renderDeleting()
	case ViewDisplaceConfirm:
		content = m.renderDisplaceConfirm()
	default:
		content = m.renderKeyListView()
	}

	// Add status bar at bottom
	statusBar := m.renderStatusBar()

	return content + "\n" + statusBar
}

// renderStatusBar renders the bottom status bar
func (m Model) renderStatusBar() string {
	var parts []string

	// Connection status
	switch m.connectionState {
	case ConnectionConnected:
		parts = append(parts, statusConnectedStyle.Render("Connected"))
	case ConnectionConnecting:
		parts = append(parts, subtitleStyle.Render("Connecting..."))
	case ConnectionDisconnected:
		parts = append(parts, statusDisconnectedStyle.Render("Disconnected (press 'c' to reconnect)"))
	}

	// Signer status
	if m.signerLocked {
		parts = append(parts, statusLockedStyle.Render("Locked"))
	} else {
		parts = append(parts, statusUnlockedStyle.Render(fmt.Sprintf("Unlocked (%d keys)", m.keyCount)))
	}

	// Warning if any
	if m.lastWarning != "" {
		parts = append(parts, warningStyle.Render("Warning: "+m.lastWarning))
	}

	// Error if any
	if m.lastError != "" {
		parts = append(parts, errorStyle.Render("Error: "+m.lastError))
	}

	return helpStyle.Render(strings.Join(parts, " | "))
}
