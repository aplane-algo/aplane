// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/apadminapp"
)

// openEnrolledClients opens the enrolled-clients screen and asks the signer
// for the waiting requests and the current registry.
func (m Model) openEnrolledClients() (tea.Model, tea.Cmd) {
	m.clients = clientsState{returnView: m.viewState, loading: true}
	m.viewState = ViewEnrolledClients
	return m, m.refreshClientsCmd()
}

// refreshClientsCmd reloads both lists shown on the screen.
func (m Model) refreshClientsCmd() tea.Cmd {
	return tea.Batch(m.sendListPendingEnrollmentsCmd(), m.sendListEnrolledKeysCmd(), m.waitForMessageCmd())
}

// clientsRowCount is the number of selectable rows: pending requests first,
// then enrolled keys.
func (m Model) clientsRowCount() int {
	return len(m.clients.pending) + len(m.clients.keys)
}

// clientsClampSelection keeps the cursor on a row after a list changes.
func (m *Model) clientsClampSelection() {
	n := m.clientsRowCount()
	if m.clients.selected >= n {
		m.clients.selected = 0
		if n > 0 {
			m.clients.selected = n - 1
		}
	}
}

func (m Model) handlePendingEnrollmentsList(msg PendingEnrollmentsListMsg) (tea.Model, tea.Cmd) {
	m.clients.pending = msg.Requests
	m.clientsClampSelection()
	return m, m.waitForMessageCmd()
}

func (m Model) handleEnrolledKeysList(msg EnrolledKeysListMsg) (tea.Model, tea.Cmd) {
	m.clients.keys = msg.Keys
	m.clients.loading = false
	m.clientsClampSelection()
	return m, m.waitForMessageCmd()
}

// handleApproveEnrollmentResult reports the signer's answer where the
// operator is looking: the Enrolled Clients status line when that screen is
// up, otherwise (an answer given from the popup) a transient footer note,
// so a failed approval is never silent.
func (m Model) handleApproveEnrollmentResult(msg ApproveEnrollmentResultMsg) (tea.Model, tea.Cmd) {
	m.settleEnrollmentAnswer(msg.Fingerprint)
	var status string
	switch {
	case msg.Success && msg.Label != "":
		status = fmt.Sprintf("Client key %s enrolled (%s).", msg.Fingerprint, msg.Label)
	case msg.Success:
		status = fmt.Sprintf("Client key %s enrolled.", msg.Fingerprint)
	default:
		status = fmt.Sprintf("Approval of %s failed: %s", msg.Fingerprint, msg.Error)
	}
	return m.reportEnrollmentAnswer(status, msg.Success)
}

func (m Model) handleRejectEnrollmentResult(msg RejectEnrollmentResultMsg) (tea.Model, tea.Cmd) {
	m.settleEnrollmentAnswer(msg.Fingerprint)
	status := fmt.Sprintf("Enrollment request for %s rejected.", msg.Fingerprint)
	if !msg.Success {
		status = fmt.Sprintf("Rejection of %s failed: %s", msg.Fingerprint, msg.Error)
	}
	return m.reportEnrollmentAnswer(status, msg.Success)
}

func (m Model) reportEnrollmentAnswer(status string, success bool) (tea.Model, tea.Cmd) {
	if success {
		m.lastError = ""
	}
	if m.viewState != ViewEnrolledClients {
		return m, tea.Batch(m.setTransientWarning(status), m.waitForMessageCmd())
	}
	m.clients.status = status
	return m, m.refreshClientsCmd()
}

func (m Model) handleImportClientKeyResult(msg ImportClientKeyResultMsg) (tea.Model, tea.Cmd) {
	if !msg.Success {
		m.clients.importError = msg.Error
		return m, m.waitForMessageCmd()
	}
	m.lastError = ""
	switch {
	case !msg.Added:
		m.clients.status = fmt.Sprintf("Client key %s was already enrolled.", msg.Fingerprint)
	case msg.Label != "":
		m.clients.status = fmt.Sprintf("Client key %s enrolled (%s).", msg.Fingerprint, msg.Label)
	default:
		m.clients.status = fmt.Sprintf("Client key %s enrolled.", msg.Fingerprint)
	}
	m.clients.importPath, m.clients.importLabel, m.clients.importError, m.clients.importFocus = "", "", "", 0
	if m.viewState == ViewImportClientKey {
		m.viewState = ViewEnrolledClients
	}
	return m, m.refreshClientsCmd()
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
	return m, m.refreshClientsCmd()
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
	return m, m.refreshClientsCmd()
}

// handleEnrolledClientsKeys handles keyboard input on the enrolled-clients
// screen. The cursor moves over waiting requests first, then enrolled keys;
// a and x answer a request, r revokes an enrolled key, A revokes every key,
// i imports a public key file.
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
		return m, m.refreshClientsCmd()
	case "up", "k":
		if m.clients.selected > 0 {
			m.clients.selected--
		}
	case "down", "j":
		if m.clients.selected < m.clientsRowCount()-1 {
			m.clients.selected++
		}
	case "a":
		if req, ok := m.selectedPendingRequest(); ok {
			m.clients.status = ""
			m.markEnrollmentAnswered(req.Fingerprint)
			return m, tea.Batch(m.sendApproveEnrollmentCmd(req.Fingerprint, ""), m.waitForMessageCmd())
		}
	case "x":
		if req, ok := m.selectedPendingRequest(); ok {
			m.clients.status = ""
			m.markEnrollmentAnswered(req.Fingerprint)
			return m, tea.Batch(m.sendRejectEnrollmentCmd(req.Fingerprint), m.waitForMessageCmd())
		}
	case "r":
		if key, ok := m.selectedEnrolledKey(); ok {
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
	case "i":
		m.clients.importPath, m.clients.importLabel, m.clients.importError, m.clients.importFocus = "", "", "", 0
		m.viewState = ViewImportClientKey
	}
	return m, nil
}

func (m Model) selectedPendingRequest() (pendingRequestRow, bool) {
	if m.clients.selected < len(m.clients.pending) {
		req := m.clients.pending[m.clients.selected]
		return pendingRequestRow{Fingerprint: req.Fingerprint, Label: req.Label}, true
	}
	return pendingRequestRow{}, false
}

type pendingRequestRow struct {
	Fingerprint string
	Label       string
}

func (m Model) selectedEnrolledKey() (enrolledKeyRow, bool) {
	index := m.clients.selected - len(m.clients.pending)
	if index >= 0 && index < len(m.clients.keys) {
		key := m.clients.keys[index]
		return enrolledKeyRow{Fingerprint: key.Fingerprint, Label: key.Label}, true
	}
	return enrolledKeyRow{}, false
}

type enrolledKeyRow struct {
	Fingerprint string
	Label       string
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

// Focus positions on the import form.
const (
	importClientKeyFocusPath = iota
	importClientKeyFocusLabel
	importClientKeyFocusButton
)

// handleImportClientKeyKeys handles keyboard input on the key import form:
// the path of a public-key file on this machine and an optional label.
func (m Model) handleImportClientKeyKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.clients.importError = ""
		m.viewState = ViewEnrolledClients
		return m, nil
	case "tab", "down":
		m.clients.importFocus = (m.clients.importFocus + 1) % 3
		return m, nil
	case "shift+tab", "up":
		m.clients.importFocus = (m.clients.importFocus + 2) % 3
		return m, nil
	case "backspace":
		switch m.clients.importFocus {
		case importClientKeyFocusPath:
			m.clients.importPath = trimLastRune(m.clients.importPath)
		case importClientKeyFocusLabel:
			m.clients.importLabel = trimLastRune(m.clients.importLabel)
		}
		m.clients.importError = ""
		return m, nil
	case "enter":
		if m.clients.importFocus < importClientKeyFocusButton {
			m.clients.importFocus++
			return m, nil
		}
		return m.submitImportClientKey()
	}
	if msg.Type == tea.KeyRunes {
		switch m.clients.importFocus {
		case importClientKeyFocusPath:
			m.clients.importPath += string(msg.Runes)
		case importClientKeyFocusLabel:
			m.clients.importLabel += string(msg.Runes)
		}
		m.clients.importError = ""
	}
	return m, nil
}

// submitImportClientKey reads the public-key file here, in the operator's
// process, and sends its one line to the signer.
func (m Model) submitImportClientKey() (tea.Model, tea.Cmd) {
	path := strings.TrimSpace(m.clients.importPath)
	if path == "" {
		m.clients.importError = "Public key file path is required"
		return m, nil
	}
	line, err := apadminapp.ReadClientPublicKeyFile(path)
	if err != nil {
		m.clients.importError = err.Error()
		return m, nil
	}
	m.clients.importError = ""
	return m, tea.Batch(m.sendImportClientKeyCmd(line, strings.TrimSpace(m.clients.importLabel)), m.waitForMessageCmd())
}
