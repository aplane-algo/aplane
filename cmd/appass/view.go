// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/theme"
)

// Styles — initialized from theme palette via init()
var (
	titleStyle    lipgloss.Style
	subtitleStyle lipgloss.Style
	statusStyle   lipgloss.Style
	warningStyle  lipgloss.Style
	errorStyle    lipgloss.Style
	helpStyle     lipgloss.Style
	selectedStyle lipgloss.Style
	normalStyle   lipgloss.Style
	disabledStyle lipgloss.Style
	successStyle  lipgloss.Style
	labelStyle    lipgloss.Style
)

func init() {
	initStyles()
}

func initStyles() {
	p := theme.Current()

	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(p.Title)).
		MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Subtitle))

	statusStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusConnected))

	warningStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Warning))

	errorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Error))

	helpStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Help))

	selectedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.SelectedFg)).
		Background(lipgloss.Color(p.Selected))

	normalStyle = lipgloss.NewStyle()

	disabledStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Help))

	successStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusConnected))

	labelStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Subtitle))
}

// View renders the current view.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	switch m.viewState {
	case ViewHome:
		return m.renderHomeView()
	case ViewPassphraseInput:
		return m.renderPassphraseView("Enter passphrase", false)
	case ViewConfirmPassphrase:
		return m.renderPassphraseView("Confirm passphrase", true)
	case ViewResult:
		return m.renderResultView()
	default:
		return ""
	}
}

// renderHomeView renders the status display and context-aware menu.
func (m Model) renderHomeView() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("appass — Auto-Unlock Manager"))
	sb.WriteString("\n")

	// Status block
	sb.WriteString(labelStyle.Render("Data directory:") + "  " + m.dataDir + "\n")

	methodDisplay := m.method
	switch m.method {
	case "none":
		methodDisplay = warningStyle.Render("none (starts locked)")
	case "passfile":
		methodDisplay = statusStyle.Render("passfile")
	case "systemd-creds":
		methodDisplay = statusStyle.Render("systemd-creds")
	case "custom":
		methodDisplay = subtitleStyle.Render("custom")
	}
	sb.WriteString(labelStyle.Render("Auto-unlock:") + "     " + methodDisplay + "\n")

	modeStr := "systemd service"
	if m.isLocal {
		modeStr = "local (no systemd service)"
	}
	sb.WriteString(labelStyle.Render("Mode:") + "            " + modeStr + "\n")
	if !m.isLocal && !m.isRoot {
		sb.WriteString(warningStyle.Render("Systemd mode changes require root; run: sudo appass -d "+m.dataDir) + "\n")
	}

	// Helper/file info when configured
	if m.method != "none" {
		helperPath, helperStatus, filePath, fileLabel, fileStatus := m.statusHelperInfo()
		if helperPath != "" {
			statusStr := statusStyle.Render(helperStatus)
			if helperStatus != "OK" {
				statusStr = errorStyle.Render(helperStatus)
			}
			sb.WriteString(labelStyle.Render("Helper binary:") + "   " + helperPath + " [" + statusStr + "]\n")
		}
		if filePath != "" {
			statusStr := statusStyle.Render(fileStatus)
			if fileStatus != "OK" {
				statusStr = errorStyle.Render(fileStatus)
			}
			sb.WriteString(labelStyle.Render(fileLabel+":") + "  " + filePath + " [" + statusStr + "]\n")
		}
	}

	sb.WriteString("\n")

	// Radio-style menu: passphrase handling mode
	sb.WriteString(subtitleStyle.Render("Passphrase handling:"))
	sb.WriteString("\n\n")

	for i, item := range m.menuItems {
		// Radio indicator for method items (not quit)
		prefix := ""
		if item.action != "quit" {
			if item.current {
				prefix = "(*) "
			} else {
				prefix = "( ) "
			}
		}

		var line string
		if item.disabled {
			note := ""
			if item.note != "" {
				note = " " + item.note
			}
			line = disabledStyle.Render(prefix + item.label + note)
		} else if item.current {
			// Current method — show as active but not highlighted
			line = statusStyle.Render(prefix + item.label + " [active]")
		} else if i == m.selectedMenu {
			line = selectedStyle.Render(prefix + item.label)
		} else {
			line = normalStyle.Render(prefix + item.label)
		}
		sb.WriteString(line + "\n")
	}

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("j/k or Up/Down: Navigate | Enter: Select | q: Quit"))

	return sb.String()
}

// renderPassphraseView renders the passphrase input screen.
func (m Model) renderPassphraseView(prompt string, isConfirm bool) string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("appass — Auto-Unlock Manager"))
	sb.WriteString("\n")

	actionLabel := m.currentAction
	switch m.currentAction {
	case "set-passfile":
		actionLabel = "Set passfile auto-unlock"
		if !isConfirm {
			sb.WriteString(warningStyle.Render("WARNING: This stores the passphrase in a plaintext file."))
			sb.WriteString("\n")
			sb.WriteString(warningStyle.Render("Passphrase file is permissioned 600."))
			sb.WriteString("\n\n")
		}
	case "set-systemd-creds":
		actionLabel = "Set systemd-creds auto-unlock"
	}

	sb.WriteString(subtitleStyle.Render(actionLabel))
	sb.WriteString("\n\n")

	sb.WriteString(prompt + ":\n")

	// Masked/visible passphrase input
	displayPass := m.passphraseInput
	if m.passphraseMasked && len(displayPass) > 0 {
		displayPass = strings.Repeat("*", len(displayPass))
	}

	inputContent := displayPass + "_"
	if len(inputContent) < 30 {
		inputContent += strings.Repeat(" ", 30-len(inputContent))
	}
	sb.WriteString("  [ " + inputContent + " ]\n\n")

	if m.passphraseError != "" {
		sb.WriteString(errorStyle.Render(m.passphraseError))
		sb.WriteString("\n\n")
	}

	sb.WriteString(helpStyle.Render("Enter: Submit | Tab: Toggle visibility | Esc: Cancel"))

	return sb.String()
}

// renderResultView renders the action result screen.
func (m Model) renderResultView() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("appass — Auto-Unlock Manager"))
	sb.WriteString("\n")

	if m.resultError != "" {
		sb.WriteString(errorStyle.Render("Error: " + m.resultError))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString(successStyle.Render("Success!"))
		sb.WriteString("\n\n")
		if m.resultMessage != "" {
			sb.WriteString(m.resultMessage)
			sb.WriteString("\n\n")
		}
	}

	// Show next steps based on action
	if m.resultError == "" {
		sb.WriteString(m.nextStepsText())
		sb.WriteString("\n")
	}

	sb.WriteString(helpStyle.Render("Press any key to return to menu"))

	return sb.String()
}

// nextStepsText returns advice after a successful action.
func (m Model) nextStepsText() string {
	switch m.currentAction {
	case "set-passfile", "set-systemd-creds":
		var sb strings.Builder
		sb.WriteString("Next steps:\n")
		if m.isLocal {
			sb.WriteString(fmt.Sprintf("  1. If keystore not initialized: apstore -d %s initialize\n", m.dataDir))
			sb.WriteString("     Use the same passphrase you entered above.\n")
			sb.WriteString("  2. Restart apsigner\n")
		} else {
			sb.WriteString(fmt.Sprintf("  1. If keystore not initialized: sudo apstore -d %s initialize\n", m.dataDir))
			sb.WriteString("     Use the same passphrase you entered above.\n")
			sb.WriteString("  2. Start/restart: sudo systemctl restart apsigner\n")
			sb.WriteString("  3. Check status:  systemctl status apsigner\n")
		}
		return sb.String()

	case "set-none":
		var sb strings.Builder
		sb.WriteString("Auto-unlock removed. The service will start locked.\n")
		if m.isLocal {
			sb.WriteString(fmt.Sprintf("  Restart apsigner, then: apadmin -d %s\n", m.dataDir))
		} else {
			sb.WriteString("  sudo systemctl restart apsigner\n")
			sb.WriteString(fmt.Sprintf("  sudo -u <service-user> apadmin -d %s\n", m.dataDir))
		}
		return sb.String()
	}
	return ""
}
