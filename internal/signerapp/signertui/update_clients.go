// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// openEnrolledClients opens the enrolled-clients screen and asks the signer
// for the waiting requests and the current registry.
func (m Model) openEnrolledClients() (tea.Model, tea.Cmd) {
	m.clients = clientsState{loading: true}
	m.viewState = ViewEnrolledClients
	return m.refreshClients()
}

// refreshClients reloads both lists shown on the screen, under new request
// IDs, so a failure of either reaches the screen.
func (m Model) refreshClients() (Model, tea.Cmd) {
	m.clients.pendingListID = newRequestID("clients-pending")
	m.clients.keysListID = newRequestID("clients-keys")
	return m, tea.Batch(m.sendListPendingEnrollmentsCmd(m.clients.pendingListID), m.sendListEnrolledKeysCmd(m.clients.keysListID))
}

// failPendingClientsList shows the failure of the list request id names on
// the screen, which otherwise stays on Loading or shows the list as empty.
func (m Model) failPendingClientsList(id string, err error) (Model, bool) {
	if id == "" {
		return m, false
	}
	switch id {
	case m.clients.pendingListID:
		m.clients.pendingListID = ""
		m.clients.pendingListErr = err.Error()
	case m.clients.keysListID:
		m.clients.keysListID = ""
		m.clients.keysListErr = err.Error()
		m.clients.loading = false
	default:
		return m, false
	}
	return m, true
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

// handleEnrollmentChanged re-fetches the Enrolled Clients lists when that
// screen (or one of its sub-views, which return to it) is up. The signer
// sends the notification for every change to the enrollment queue or the
// client registry, whatever made it: this session's own answers, a request
// arriving over SSH, or an answer given from another admin client. Off the
// screen there is nothing to refresh; the screen loads afresh when opened.
func (m Model) handleEnrollmentChanged() (tea.Model, tea.Cmd) {
	if m.showsEnrolledClients() {
		return m.refreshClients()
	}
	return m, nil
}

// showsEnrolledClients reports whether the Enrolled Clients lists are on
// screen or will be once the view on top returns: the screen itself, its
// sub-views, or an approval popup raised over it (a request's own popup is
// up when its enrollment_changed arrives, and Esc returns to the list).
func (m Model) showsEnrolledClients() bool {
	view := m.viewState
	if m.approvalPending(view) {
		view = m.screenUnderApproval()
	}
	switch view {
	case ViewEnrolledClients, ViewRevokeClientConfirm, ViewImportClientKey:
		return true
	}
	return false
}

func (m Model) handlePendingEnrollmentsList(msg PendingEnrollmentsListMsg) (tea.Model, tea.Cmd) {
	m.clients.pending = msg.Requests
	m.clients.pendingListErr = ""
	m.clientsClampSelection()
	return m, nil
}

func (m Model) handleEnrolledKeysList(msg EnrolledKeysListMsg) (tea.Model, tea.Cmd) {
	m.clients.keys = msg.Keys
	m.clients.loading = false
	m.clients.keysListErr = ""
	m.clientsClampSelection()
	return m, nil
}

// handleApproveEnrollmentResult reports the signer's answer where the
// operator is looking: the Enrolled Clients status line when that screen is
// up, otherwise (an answer given from the popup) the status bar, so a failed
// approval is never silent.
func (m Model) handleApproveEnrollmentResult(msg ApproveEnrollmentResultMsg) (tea.Model, tea.Cmd) {
	m.settleEnrollmentAnswer(msg.Fingerprint)
	status := func(fingerprint string) string {
		switch {
		case msg.Success && msg.Label != "":
			return fmt.Sprintf("Enrolled %s (%s).", fingerprint, msg.Label)
		case msg.Success:
			return fmt.Sprintf("Enrolled %s.", fingerprint)
		default:
			return fmt.Sprintf("Approval of %s failed: %s", fingerprint, msg.Error)
		}
	}
	return m.reportEnrollmentAnswer(msg.Fingerprint, msg.Success, status)
}

func (m Model) handleRejectEnrollmentResult(msg RejectEnrollmentResultMsg) (tea.Model, tea.Cmd) {
	m.settleEnrollmentAnswer(msg.Fingerprint)
	status := func(fingerprint string) string {
		if !msg.Success {
			return fmt.Sprintf("Rejection of %s failed: %s", fingerprint, msg.Error)
		}
		return fmt.Sprintf("Rejected %s.", fingerprint)
	}
	return m.reportEnrollmentAnswer(msg.Fingerprint, msg.Success, status)
}

// reportEnrollmentAnswer takes the status as a function of the fingerprint
// because the status bar shares one line with the connection state: there
// the fingerprint is shortened so the outcome stays on screen. A success is
// a notice, not a warning.
func (m Model) reportEnrollmentAnswer(
	fingerprint string,
	success bool,
	status func(fingerprint string) string,
) (tea.Model, tea.Cmd) {
	if success {
		m.lastError = ""
	}
	if m.viewState == ViewEnrolledClients {
		m.clients.status = status(fingerprint)
		return m.refreshClients()
	}
	var clearCmd tea.Cmd
	if success {
		clearCmd = m.setTransientNotice(status(shortDigest(fingerprint)))
	} else {
		clearCmd = m.setTransientWarning(status(shortDigest(fingerprint)))
	}
	return m, clearCmd
}

func (m Model) handleImportClientKeyResult(msg ImportClientKeyResultMsg) (tea.Model, tea.Cmd) {
	if !msg.Success {
		m.clients.importError = msg.Error
		return m, nil
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
	return m.refreshClients()
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
	return m.refreshClients()
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
	return m.refreshClients()
}

// handleEnrolledClientsKeys handles keyboard input on the enrolled-clients
// screen. The cursor moves over waiting requests first, then enrolled keys;
// a and x answer a request, r revokes an enrolled key, A revokes every key,
// i imports a public key file. There is no manual refresh: the signer's
// enrollment_changed notification keeps the lists current.
func (m Model) handleEnrolledClientsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewKeyList
		m.clients = clientsState{}
		return m, nil
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
			return m, m.sendApproveEnrollmentCmd(req.Fingerprint, "")
		}
	case "x":
		if req, ok := m.selectedPendingRequest(); ok {
			m.clients.status = ""
			m.markEnrollmentAnswered(req.Fingerprint)
			return m, m.sendRejectEnrollmentCmd(req.Fingerprint)
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

func (m Model) selectedPendingRequest() (protocol.PendingEnrollmentInfo, bool) {
	if m.clients.selected < len(m.clients.pending) {
		return m.clients.pending[m.clients.selected], true
	}
	return protocol.PendingEnrollmentInfo{}, false
}

func (m Model) selectedEnrolledKey() (protocol.EnrolledKeyInfo, bool) {
	index := m.clients.selected - len(m.clients.pending)
	if index >= 0 && index < len(m.clients.keys) {
		return m.clients.keys[index], true
	}
	return protocol.EnrolledKeyInfo{}, false
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
		return m, m.sendRevokeAllEnrolledKeysCmd()
	}
	return m, m.sendRevokeEnrolledKeyCmd(m.clients.confirmKey)
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
	case fileBrowserKey:
		m.clients.importFocus = importClientKeyFocusPath
		return m.openFileBrowser(browseClientKeyFile, m.clients.importPath, ""), nil
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
	return m, m.sendImportClientKeyCmd(line, strings.TrimSpace(m.clients.importLabel))
}
