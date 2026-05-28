// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	tea "github.com/charmbracelet/bubbletea"
)

// Update handles all messages and key events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case StatusLoadedMsg:
		m.method = msg.method
		m.isLocal = msg.isLocal
		m.svcInfo = msg.svcInfo
		m.menuItems = m.buildMenu()
		// Select first item that isn't current or disabled
		m.selectedMenu = 0
		for i, item := range m.menuItems {
			if !item.current && !item.disabled {
				m.selectedMenu = i
				break
			}
		}
		return m, nil

	case ActionDoneMsg:
		if msg.err != nil {
			m.resultError = msg.err.Error()
			m.resultMessage = ""
		} else {
			m.resultError = ""
			m.resultMessage = msg.warning
		}
		m.viewState = ViewResult
		return m, nil

	case tea.KeyMsg:
		switch m.viewState {
		case ViewHome:
			return m.handleHomeKeys(msg)
		case ViewPassphraseInput:
			return m.handlePassphraseInputKeys(msg)
		case ViewConfirmPassphrase:
			return m.handleConfirmKeys(msg)
		case ViewResult:
			return m.handleResultKeys(msg)
		}
	}

	return m, nil
}

// handleHomeKeys handles key input on the home/menu screen.
func (m Model) handleHomeKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.quitting = true
		return m, tea.Quit

	case "up", "k":
		for {
			m.selectedMenu--
			if m.selectedMenu < 0 {
				m.selectedMenu = len(m.menuItems) - 1
			}
			if !m.menuItems[m.selectedMenu].disabled && !m.menuItems[m.selectedMenu].current {
				break
			}
		}

	case "down", "j":
		for {
			m.selectedMenu++
			if m.selectedMenu >= len(m.menuItems) {
				m.selectedMenu = 0
			}
			if !m.menuItems[m.selectedMenu].disabled && !m.menuItems[m.selectedMenu].current {
				break
			}
		}

	case "enter":
		if m.selectedMenu >= len(m.menuItems) {
			return m, nil
		}
		item := m.menuItems[m.selectedMenu]
		if item.disabled || item.current {
			return m, nil
		}

		switch item.action {
		case "quit":
			m.quitting = true
			return m, tea.Quit
		case "set-none":
			m.currentAction = "set-none"
			return m.dispatchAction(nil)
		case "set-passfile", "set-systemd-creds":
			m.currentAction = item.action
			m.passphraseInput = ""
			m.passphraseFirst = ""
			m.passphraseError = ""
			m.passphraseMasked = true
			m.viewState = ViewPassphraseInput
		}
	}

	return m, nil
}

// handlePassphraseInputKeys handles key input on the first passphrase entry screen.
func (m Model) handlePassphraseInputKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.viewState = ViewHome
		m.passphraseInput = ""
		m.passphraseError = ""
		return m, nil

	case "enter":
		if m.passphraseInput == "" {
			m.passphraseError = "Passphrase must not be empty"
			return m, nil
		}
		m.passphraseFirst = m.passphraseInput
		m.passphraseInput = ""
		m.passphraseError = ""
		m.viewState = ViewConfirmPassphrase

	case "backspace":
		if len(m.passphraseInput) > 0 {
			m.passphraseInput = m.passphraseInput[:len(m.passphraseInput)-1]
			m.passphraseError = ""
		}

	case "tab":
		m.passphraseMasked = !m.passphraseMasked

	default:
		if len(msg.String()) == 1 {
			m.passphraseInput += msg.String()
			m.passphraseError = ""
		}
	}

	return m, nil
}

// handleConfirmKeys handles key input on the confirm passphrase screen.
func (m Model) handleConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.viewState = ViewHome
		m.passphraseInput = ""
		m.passphraseFirst = ""
		m.passphraseError = ""
		return m, nil

	case "enter":
		if m.passphraseInput != m.passphraseFirst {
			m.passphraseError = "Passphrases do not match"
			m.passphraseInput = ""
			return m, nil
		}
		passphrase := []byte(m.passphraseInput)
		m.passphraseInput = ""
		m.passphraseFirst = ""
		return m.dispatchAction(passphrase)

	case "backspace":
		if len(m.passphraseInput) > 0 {
			m.passphraseInput = m.passphraseInput[:len(m.passphraseInput)-1]
			m.passphraseError = ""
		}

	case "tab":
		m.passphraseMasked = !m.passphraseMasked

	default:
		if len(msg.String()) == 1 {
			m.passphraseInput += msg.String()
			m.passphraseError = ""
		}
	}

	return m, nil
}

// handleResultKeys handles key input on the result screen — any key returns to home.
func (m Model) handleResultKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.viewState = ViewHome
	m.resultMessage = ""
	m.resultError = ""
	return m, loadStatusCmd(m.dataDir, m.identityID)
}

// dispatchAction runs the current action directly in-process.
func (m Model) dispatchAction(passphrase []byte) (tea.Model, tea.Cmd) {
	action := m.currentAction
	dataDir := m.dataDir
	identityID := m.identityID
	svcInfo := m.svcInfo
	isLocal := m.isLocal
	return m, func() tea.Msg {
		var (
			err     error
			warning string
		)
		switch action {
		case "set-passfile":
			warning, err = executeSetPassfile(dataDir, identityID, passphrase, svcInfo, isLocal)
		case "set-systemd-creds":
			warning, err = executeSetSystemcreds(dataDir, identityID, passphrase, svcInfo)
		case "set-none":
			warning, err = executeClear(dataDir, identityID)
		}
		return ActionDoneMsg{err: err, warning: warning}
	}
}
