// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

import tea "github.com/charmbracelet/bubbletea"

// handleAuthKeys handles keyboard input on authentication screen
func (m Model) handleAuthKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.handlePassphraseKeys(msg, func(passphrase string) tea.Cmd {
		return tea.Batch(SendAuthCmd(passphrase), WaitForMessageCmd())
	})
}

// handleUnlockKeys handles keyboard input on unlock screen
func (m Model) handleUnlockKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.handlePassphraseKeys(msg, func(passphrase string) tea.Cmd {
		return sendUnlockRequest(passphrase)
	})
}

// handlePassphraseKeys handles common keyboard input for passphrase entry screens
func (m Model) handlePassphraseKeys(msg tea.KeyMsg, onSubmit func(string) tea.Cmd) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.quitting = true
		return m, tea.Quit

	case "c":
		// Allow reconnect when disconnected
		if m.connectionState == ConnectionDisconnected {
			m.connectionState = ConnectionConnecting
			m.passphraseInput = ""
			return m, ReconnectCmd(m.ipcPath)
		}
		// Otherwise treat as regular character
		m.passphraseInput += msg.String()
		m.passphraseError = "" // Clear error on input

	case "enter":
		// Don't submit if disconnected
		if m.connectionState == ConnectionDisconnected {
			return m, nil
		}
		if m.passphraseInput != "" {
			m.loggingIn = true
			return m, onSubmit(m.passphraseInput)
		}

	case "backspace":
		if len(m.passphraseInput) > 0 {
			m.passphraseInput = m.passphraseInput[:len(m.passphraseInput)-1]
			m.passphraseError = "" // Clear error on input
		}

	case "tab":
		// Toggle passphrase visibility
		m.passphraseMasked = !m.passphraseMasked

	default:
		// Add character to passphrase input (only when connected)
		if m.connectionState != ConnectionDisconnected && len(msg.String()) == 1 {
			m.passphraseInput += msg.String()
			m.passphraseError = "" // Clear error on input
		}
	}

	return m, nil
}
