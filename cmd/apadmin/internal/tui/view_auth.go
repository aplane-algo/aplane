// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

// Authentication and unlock view rendering.

import "strings"

// renderAuthView renders the IPC authentication screen
func (m Model) renderAuthView() string {
	return m.renderPassphrasePrompt("Enter passphrase to authenticate")
}

// renderUnlockView renders the unlock/passphrase entry screen
func (m Model) renderUnlockView() string {
	return m.renderPassphrasePrompt("Enter passphrase to unlock Signer")
}

// renderPassphrasePrompt renders a generic passphrase entry screen with the given subtitle
func (m Model) renderPassphrasePrompt(subtitle string) string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("SignerAdmin TUI"))
	sb.WriteString("\n")

	// Show connection error prominently if disconnected
	if m.connectionState == ConnectionDisconnected {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render("⚠ Server not responding"))
		sb.WriteString("\n")
		sb.WriteString(helpStyle.Render("Is apsignerd running? Press 'c' to retry connection."))
		sb.WriteString("\n\n")
		sb.WriteString(helpStyle.Render("Esc: Quit"))
		return sb.String()
	}

	if m.connectionState == ConnectionConnecting {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Connecting to server..."))
		sb.WriteString("\n\n")
		sb.WriteString(helpStyle.Render("Esc: Quit"))
		return sb.String()
	}

	if m.loggingIn {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Logging in..."))
		sb.WriteString("\n\n")
		sb.WriteString(helpStyle.Render("Esc: Quit"))
		return sb.String()
	}

	sb.WriteString(subtitleStyle.Render(subtitle))
	sb.WriteString("\n\n")

	// Passphrase input
	displayPass := m.passphraseInput
	if m.passphraseMasked && len(displayPass) > 0 {
		displayPass = strings.Repeat("*", len(displayPass))
	}

	sb.WriteString("Passphrase:\n")
	inputContent := displayPass + "_"
	if len(inputContent) < 30 {
		inputContent += strings.Repeat(" ", 30-len(inputContent))
	}
	sb.WriteString("  [ " + inputContent + " ]\n\n")

	// Error message
	if m.passphraseError != "" {
		sb.WriteString(errorStyle.Render(m.passphraseError))
		sb.WriteString("\n\n")
	}

	// Help
	sb.WriteString(helpStyle.Render("Enter: Submit | Tab: Toggle visibility | Esc: Quit"))

	return sb.String()
}
