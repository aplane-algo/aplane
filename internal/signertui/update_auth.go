// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import tea "github.com/charmbracelet/bubbletea"

// handleAuthKeys handles keyboard input on authentication screen
func (m Model) handleAuthKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.handlePassphraseKeys(msg, func(passphrase string) tea.Cmd {
		return tea.Batch(m.sendAuthCmd(passphrase), m.waitForMessageCmd())
	})
}

// handleUnlockKeys handles keyboard input on unlock screen
func (m Model) handleUnlockKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.handlePassphraseKeys(msg, func(passphrase string) tea.Cmd {
		return m.sendUnlockRequest(passphrase)
	})
}

// handlePassphraseKeys handles common keyboard input for passphrase entry screens
func (m Model) handlePassphraseKeys(msg tea.KeyMsg, onSubmit func(string) tea.Cmd) (tea.Model, tea.Cmd) {
	switch msg.String() {
	// "q" is deliberately not a quit key here: passphrases may contain it.
	// Quitting is available via esc (below) and the global ctrl+c handler.
	case "esc":
		m.quitting = true
		return m, tea.Quit

	case "c":
		// Allow reconnect when disconnected
		if m.connectionState == ConnectionDisconnected {
			m.connectionState = ConnectionConnecting
			m.auth.passphraseInput = ""
			return m, m.reconnectCmd()
		}
		// Otherwise treat as regular character
		m.auth.passphraseInput += msg.String()
		m.auth.passphraseError = "" // Clear error on input

	case "enter":
		// Don't submit if disconnected
		if m.connectionState == ConnectionDisconnected {
			return m, nil
		}
		if m.auth.passphraseInput != "" {
			m.auth.loggingIn = true
			return m, onSubmit(m.auth.passphraseInput)
		}

	case "backspace":
		if len(m.auth.passphraseInput) > 0 {
			m.auth.passphraseInput = m.auth.passphraseInput[:len(m.auth.passphraseInput)-1]
			m.auth.passphraseError = "" // Clear error on input
		}

	case "tab":
		// Toggle passphrase visibility
		m.auth.passphraseMasked = !m.auth.passphraseMasked

	default:
		// Add character to passphrase input (only when connected)
		if m.connectionState != ConnectionDisconnected && len(msg.String()) == 1 {
			m.auth.passphraseInput += msg.String()
			m.auth.passphraseError = "" // Clear error on input
		}
	}

	return m, nil
}
