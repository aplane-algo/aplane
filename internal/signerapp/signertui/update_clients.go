// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// openEnrolledClients opens the enrolled-clients screen and asks the signer
// for the current registry.
func (m Model) openEnrolledClients() (tea.Model, tea.Cmd) {
	m.clients = clientsState{returnView: m.viewState, loading: true}
	m.viewState = ViewEnrolledClients
	return m, tea.Batch(m.sendListEnrolledKeysCmd(), m.waitForMessageCmd())
}

func (m Model) handleEnrolledKeysList(msg EnrolledKeysListMsg) (tea.Model, tea.Cmd) {
	m.clients.keys = msg.Keys
	m.clients.loading = false
	if m.clients.selected >= len(m.clients.keys) {
		m.clients.selected = 0
		if n := len(m.clients.keys); n > 0 {
			m.clients.selected = n - 1
		}
	}
	return m, m.waitForMessageCmd()
}

func (m Model) handleRevokeEnrolledKeyResult(msg RevokeEnrolledKeyResultMsg) (tea.Model, tea.Cmd) {
	if m.viewState == ViewRevokeClientConfirm {
		m.viewState = ViewEnrolledClients
	}
	if msg.Success {
		m.lastError = ""
		m.clients.status = fmt.Sprintf("Client key revoked; closed %d connection(s).", msg.ClosedConnections)
	} else {
		m.clients.status = "Revocation failed: " + msg.Error
	}
	m.clients.loading = true
	return m, tea.Batch(m.sendListEnrolledKeysCmd(), m.waitForMessageCmd())
}

func (m Model) handleRevokeAllEnrolledKeysResult(msg RevokeAllEnrolledKeysResultMsg) (tea.Model, tea.Cmd) {
	if m.viewState == ViewRevokeClientConfirm {
		m.viewState = ViewEnrolledClients
	}
	if msg.Success {
		m.lastError = ""
		m.clients.status = fmt.Sprintf("Revoked %d client key(s); closed %d connection(s). Clients must re-enroll.", msg.RevokedCount, msg.ClosedConnections)
	} else {
		m.clients.status = "Revocation failed: " + msg.Error
	}
	m.clients.loading = true
	return m, tea.Batch(m.sendListEnrolledKeysCmd(), m.waitForMessageCmd())
}

// handleEnrolledClientsKeys handles keyboard input on the enrolled-clients
// screen.
func (m Model) handleEnrolledClientsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = m.clients.returnView
		if m.viewState == 0 {
			m.viewState = ViewAdminPanel
		}
		m.clients = clientsState{}
		return m, nil
	case "R":
		m.clients.status = ""
		m.clients.loading = true
		return m, tea.Batch(m.sendListEnrolledKeysCmd(), m.waitForMessageCmd())
	case "up", "k":
		if m.clients.selected > 0 {
			m.clients.selected--
		}
	case "down", "j":
		if m.clients.selected < len(m.clients.keys)-1 {
			m.clients.selected++
		}
	case "r":
		if m.clients.selected < len(m.clients.keys) {
			key := m.clients.keys[m.clients.selected]
			m.clients.confirmAll = false
			m.clients.confirmKey = key.Fingerprint
			m.clients.confirmLabel = key.Label
			m.clients.confirmFocus = 0
			m.viewState = ViewRevokeClientConfirm
		}
	case "A":
		if len(m.clients.keys) > 0 {
			m.clients.confirmAll = true
			m.clients.confirmKey = ""
			m.clients.confirmLabel = ""
			m.clients.confirmFocus = 0
			m.viewState = ViewRevokeClientConfirm
		}
	}
	return m, nil
}

// handleRevokeClientConfirmKeys handles keyboard input on the client key
// revocation confirmation dialog. Cancel is the default.
func (m Model) handleRevokeClientConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		m.viewState = ViewEnrolledClients
		return m, nil
	case "tab", "left", "right", "h", "l":
		m.clients.confirmFocus = (m.clients.confirmFocus + 1) % 2
		return m, nil
	case "enter", " ":
		if m.clients.confirmFocus == 0 {
			m.viewState = ViewEnrolledClients
			return m, nil
		}
		return m.sendClientRevocation()
	case "y":
		return m.sendClientRevocation()
	}
	return m, nil
}

func (m Model) sendClientRevocation() (tea.Model, tea.Cmd) {
	m.clients.status = ""
	if m.clients.confirmAll {
		return m, tea.Batch(m.sendRevokeAllEnrolledKeysCmd(), m.waitForMessageCmd())
	}
	return m, tea.Batch(m.sendRevokeEnrolledKeyCmd(m.clients.confirmKey), m.waitForMessageCmd())
}
