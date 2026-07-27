// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// openRecoveredList shows the recovered-batch inventory. While the signer is
// in recovery mode this is the blocking screen: signing is disabled
// server-side and ordinary navigation stays unavailable until every
// incomplete activation is resolved.
func (m Model) openRecoveredList() (tea.Model, tea.Cmd) {
	m.restore.recoveredLoaded = false
	m.restore.purgeArmedID = ""
	m.viewState = ViewRecoveredList
	return m, tea.Batch(m.sendListRecoveredCmd(), m.waitForMessageCmd())
}

func (m Model) currentRecoveredBatch() (RecoveredBatchInfo, bool) {
	if len(m.restore.recovered) == 0 ||
		m.restore.selectedRecovered < 0 ||
		m.restore.selectedRecovered >= len(m.restore.recovered) {
		return RecoveredBatchInfo{}, false
	}
	return m.restore.recovered[m.restore.selectedRecovered], true
}

func (m *Model) clampRecoveredSelection() {
	if m.restore.selectedRecovered >= len(m.restore.recovered) {
		m.restore.selectedRecovered = len(m.restore.recovered) - 1
	}
	if m.restore.selectedRecovered < 0 {
		m.restore.selectedRecovered = 0
	}
	if m.restore.recoveredScrollOffset > m.restore.selectedRecovered {
		m.restore.recoveredScrollOffset = m.restore.selectedRecovered
	}
}

func (m Model) handleRecoveredListKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// A pending purge is a two-step confirmation: y commits, anything else
	// disarms.
	if m.restore.purgeArmedID != "" {
		switch msg.String() {
		case "y", "Y":
			restoreID := m.restore.purgeArmedID
			m.restore.purgeArmedID = ""
			m.restore.recoveredError = ""
			m.restore.progressLabel = "Purging Recovered Batch"
			m.viewState = ViewRestoring
			return m, tea.Batch(m.sendPurgeRecoveredCmd(restoreID), m.waitForMessageCmd())
		default:
			m.restore.purgeArmedID = ""
			m.restore.recoveredError = ""
			return m, nil
		}
	}

	switch msg.String() {
	case "q", "esc":
		if m.signerState == signerRuntimeRecovery {
			if msg.String() == "q" {
				// The footer advertises "q: Quit" and quitting the TUI is
				// safe: recovery state is durable server-side. Esc keeps
				// the blocking message — there is no screen to go back to.
				return m, tea.Quit
			}
			// Blocking: there is no normal navigation to return to while
			// signing is disabled.
			m.restore.recoveredError = "Signing is disabled until every incomplete activation is resolved"
			return m, nil
		}
		m.restore.recoveredError = ""
		m.viewState = ViewRestoreList
		return m, tea.Batch(m.sendListBackupsCmd(), m.waitForMessageCmd())
	case "r", "R":
		m.restore.recoveredLoaded = false
		m.restore.recoveredError = ""
		return m, tea.Batch(m.sendListRecoveredCmd(), m.waitForMessageCmd())
	case "up", "k":
		if m.restore.selectedRecovered > 0 {
			m.restore.selectedRecovered--
			if m.restore.selectedRecovered < m.restore.recoveredScrollOffset {
				m.restore.recoveredScrollOffset = m.restore.selectedRecovered
			}
		}
	case "down", "j":
		if m.restore.selectedRecovered < len(m.restore.recovered)-1 {
			m.restore.selectedRecovered++
			visible := m.recoveredVisibleHeight()
			if m.restore.selectedRecovered >= m.restore.recoveredScrollOffset+visible {
				m.restore.recoveredScrollOffset = m.restore.selectedRecovered - visible + 1
			}
		}
	case "enter":
		// Reopen for review; an incomplete activation resumes through the
		// same review with its recorded intent. No passphrase is required.
		batch, ok := m.currentRecoveredBatch()
		if !ok {
			return m, nil
		}
		m.restore.restoreID = batch.RestoreID
		m.restore.recoveredError = ""
		m.restore.progressLabel = "Loading Activation Review"
		m.viewState = ViewRestoring
		return m, tea.Batch(m.sendReviewRecoveredCmd(batch.RestoreID), m.waitForMessageCmd())
	case "x", "X":
		// Rollback: restore the exact pre-activation state. The default
		// resolution for an interrupted activation.
		batch, ok := m.currentRecoveredBatch()
		if !ok {
			return m, nil
		}
		if batch.ActivationState == "" {
			m.restore.recoveredError = "Batch is inactive; nothing to roll back"
			return m, nil
		}
		if batch.ActivationState == "completed" {
			m.restore.recoveredError = "Activation already completed; press Enter to finish its cleanup instead"
			return m, nil
		}
		m.restore.recoveredError = ""
		m.restore.progressLabel = "Rolling Back Incomplete Activation"
		m.viewState = ViewRestoring
		return m, tea.Batch(m.sendRollbackRecoveredCmd(batch.RestoreID), m.waitForMessageCmd())
	case "p", "P":
		batch, ok := m.currentRecoveredBatch()
		if !ok {
			return m, nil
		}
		if batch.ActivationState != "" {
			m.restore.recoveredError = "Cannot purge a batch with an incomplete activation"
			return m, nil
		}
		if m.signerState == signerRuntimeRecovery {
			m.restore.recoveredError = "Resolve every incomplete activation before purging"
			return m, nil
		}
		m.restore.purgeArmedID = batch.RestoreID
		m.restore.recoveredError = fmt.Sprintf("Press y to confirm purge of batch %s", batch.RestoreID)
	}
	return m, nil
}
