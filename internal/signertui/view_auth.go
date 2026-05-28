// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Authentication and unlock view rendering.

import (
	"fmt"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// renderAuthView renders the IPC authentication screen
func (m Model) renderAuthView() string {
	return m.renderPassphrasePrompt("Enter passphrase to authenticate", false)
}

// renderUnlockView renders the unlock/passphrase entry screen
func (m Model) renderUnlockView() string {
	return m.renderPassphrasePrompt("Enter passphrase to unlock Signer", true)
}

// renderPassphrasePrompt renders a generic passphrase entry screen with the given subtitle
func (m Model) renderPassphrasePrompt(subtitle string, showTimeout bool) string {
	var sb strings.Builder

	// Show connection error prominently if disconnected
	if m.connectionState == ConnectionDisconnected {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render("⚠ Server not responding"))
		sb.WriteString("\n")
		sb.WriteString(helpStyle.Render("Is apsigner running? Press 'c' to retry connection."))
		return sb.String()
	}

	if m.connectionState == ConnectionConnecting {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Connecting to server..."))
		return sb.String()
	}

	if m.loggingIn {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Logging in..."))
		return sb.String()
	}

	sb.WriteString(subtitleStyle.Render(subtitle))
	if showTimeout {
		if notice := m.adminInactivityNotice(); notice != "" {
			sb.WriteString("\n")
			sb.WriteString(helpStyle.Render(notice))
		}
	}
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

	return sb.String()
}

func (m Model) adminInactivityNotice() string {
	timeout := m.effectiveSessionTimeout
	if timeout <= 0 && m.adminSettings != nil && m.adminSettings.PassphraseTimeout != "" {
		parsed, err := apconfig.ParsePassphraseTimeout(m.adminSettings.PassphraseTimeout)
		if err == nil {
			timeout = parsed
		}
	}
	if timeout > 0 {
		return fmt.Sprintf("Signer locks after %s of admin inactivity", timeout)
	}
	if m.adminSettings != nil && strings.TrimSpace(m.adminSettings.PassphraseTimeout) == "0" {
		return "Signer inactivity lock is disabled"
	}
	return ""
}
