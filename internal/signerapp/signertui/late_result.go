// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import tea "github.com/charmbracelet/bubbletea"

// A generate, import or backup whose success arrives after a lock (or a move
// into recovery) took the operator off its progress screen still happened.
// Its result is not shown over the screen that took over; it is held and
// shown once the operator is back on the key list of an unlocked signer, so
// the generated account's receipt, for one, can still be saved. It is held
// only within the session it arrived in; when the session ends it is
// discarded. A late failure changed nothing and is dropped.

// holdLateSuccess keeps result when it is a success for the operation the
// TUI started, which a reply for any other request is not.
func (m Model) holdLateSuccess(id string, success bool, result tea.Msg) Model {
	if !success || id == "" || id != m.operation.id {
		return m
	}
	m.operation = pendingOperation{}
	m.heldResult = result
	return m
}

// showHeldResult shows a held result once the TUI is on the key list of an
// unlocked signer, where unlocking leads.
func (m Model) showHeldResult() (Model, tea.Cmd) {
	if m.heldResult == nil || m.signerState != signerRuntimeUnlocked || m.viewState != ViewKeyList {
		return m, nil
	}
	held := m.heldResult
	m.heldResult = nil
	var next tea.Model
	var cmd tea.Cmd
	switch result := held.(type) {
	case GenerateResultMsg:
		next, cmd = m.applyGenerateResult(result)
	case ImportResultMsg:
		next, cmd = m.applyImportResult(result)
	case BackupResultMsg:
		next, cmd = m.applyBackupResult(result)
	default:
		return m, nil
	}
	return next.(Model), cmd
}
