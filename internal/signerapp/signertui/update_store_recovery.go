// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import tea "github.com/charmbracelet/bubbletea"

func (m Model) openStoreRecovery() (tea.Model, tea.Cmd) {
	m.restore.recoveryError = ""
	m.viewState = ViewStoreRecovery
	return m, m.waitForMessageCmd()
}

func (m Model) handleStoreRecoveryKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "esc":
		if m.signerState == signerRuntimeRecovery {
			m.restore.recoveryError = "Signing remains disabled until the store validates cleanly"
			return m, nil
		}
		m.viewState = ViewKeyList
		return m, nil
	case "r", "R":
		m.restore.recoveryError = ""
		m.restore.progressLabel = "Reconciling Store"
		m.viewState = ViewRestoring
		return m, tea.Batch(m.sendReconcileStoreCmd(), m.waitForMessageCmd())
	case "x", "X":
		m.restore.recoveryError = ""
		m.restore.progressLabel = "Rolling Back Latest Credential Restore"
		m.viewState = ViewRestoring
		return m, tea.Batch(m.sendRollbackRestoreCmd(), m.waitForMessageCmd())
	case "b", "B":
		return m.openRestoreList()
	case "l", "L":
		return m, tea.Batch(
			m.sendLockIdentityCmd("operator locked signer from store recovery"),
			m.waitForMessageCmd(),
		)
	}
	return m, nil
}
