// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/secretbuf"
)

// clearAuthPassphrase zeroes and drops the login or unlock passphrase.
func (m *Model) clearAuthPassphrase() {
	m.auth.passphraseInput.Zero()
	m.auth.passphraseInput = nil
}

// handleAuthKeys handles keyboard input on authentication screen
func (m Model) handleAuthKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.handlePassphraseKeys(msg, m.sendAuthCmd)
}

// handleUnlockKeys handles keyboard input on unlock screen
func (m Model) handleUnlockKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.handlePassphraseKeys(msg, m.sendUnlockCmd)
}

// handlePassphraseKeys handles common keyboard input for passphrase entry
// screens. onSubmit must copy the passphrase it sends: the field stays until
// the result arrives and is zeroed then.
func (m Model) handlePassphraseKeys(msg tea.KeyMsg, onSubmit func([]byte) tea.Cmd) (tea.Model, tea.Cmd) {
	switch msg.String() {
	// "q" is deliberately not a quit key here: passphrases may contain it.
	// Quitting is available via esc (below) and the global ctrl+c handler.
	case "esc":
		m.quitting = true
		return m, tea.Quit

	case "enter":
		// Don't submit if disconnected
		if m.connectionState == ConnectionDisconnected {
			return m, nil
		}
		if len(m.auth.passphraseInput) > 0 {
			m.auth.loggingIn = true
			return m, onSubmit(m.auth.passphraseInput)
		}

	case "backspace":
		if len(m.auth.passphraseInput) > 0 {
			m.auth.passphraseInput = secretbuf.TrimRune(m.auth.passphraseInput)
			m.auth.passphraseError = "" // Clear error on input
		}

	case "tab":
		// Toggle passphrase visibility
		m.auth.passphraseMasked = !m.auth.passphraseMasked

	default:
		// Add character to passphrase input (only when connected; while
		// disconnected, handleKeyPress takes "c" as reconnect first).
		if m.connectionState != ConnectionDisconnected && len(msg.String()) == 1 {
			m.auth.passphraseInput = secretbuf.AppendText(m.auth.passphraseInput, msg.String())
			m.auth.passphraseError = "" // Clear error on input
		}
	}

	return m, nil
}
