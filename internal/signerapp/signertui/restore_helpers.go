// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "github.com/aplane-algo/aplane/internal/crypto"

func (m *Model) clearRestorePassphrase() {
	crypto.ZeroBytes(m.restore.passphrase)
	m.restore.passphrase = nil
}

// beginRestoreRequest names a new preview, restore, rollback or reconcile
// request and returns the ID it must carry.
func (m *Model) beginRestoreRequest(prefix string) string {
	m.restore.pendingID = newRequestID(prefix)
	return m.restore.pendingID
}

// failRestoreRequest handles an untyped failure (an authorization denial,
// service unavailable, a send error) of the request beginRestoreRequest
// named. A failure that names any other request, such as a background
// refresh, is not the restore's and must not zero the passphrase the
// preview step still needs.
func (m Model) failRestoreRequest(err error) Model {
	m.restore.pendingID = ""
	if m.viewState == ViewRestorePassphrase || m.viewState == ViewRestorePreview || m.viewState == ViewRestoring {
		m.clearRestorePassphrase()
		m.restore.previewing = false
	}
	if m.viewState != ViewRestoring {
		m.lastError = err.Error()
		return m
	}
	// The progress screen refuses Esc, so the failure must not strand the
	// operator there. Route it the way typed failures are.
	if m.signerState == signerRuntimeRecovery {
		m.viewState = ViewStoreRecovery
		m.restore.recoveryError = err.Error()
		return m
	}
	m.lastError = err.Error()
	m.viewState = ViewBackups
	return m
}

func (m *Model) resetRestoreFlow() {
	m.clearRestorePassphrase()
	m.restore = restoreState{}
}

func (m Model) currentRestoreBackup() (BackupInfo, bool) {
	if len(m.restore.backups) == 0 || m.restore.selectedBackup < 0 || m.restore.selectedBackup >= len(m.restore.backups) {
		return BackupInfo{}, false
	}
	return m.restore.backups[m.restore.selectedBackup], true
}

// initializeRestoreSelection selects every new key. Conflicting
// (already-existing) keys stay selectable: the replace-existing consent is
// collected on the restore confirmation beside the exact conflicts it
// authorizes.
func (m *Model) initializeRestoreSelection() {
	m.restore.selected = make(map[string]bool)
	for _, key := range m.restore.previewKeys {
		if !key.AlreadyExists {
			m.restore.selected[key.Address] = true
		}
	}
	m.clampRestoreSelection()
}

// restorePreviewRowCount is the length of the preview list: the keys the
// restore would admit, then those it skips.
func (m Model) restorePreviewRowCount() int {
	return len(m.restore.previewKeys) + len(m.restore.previewSkipped)
}

// highlightedSkipped is the skipped key under the preview cursor, if any.
func (m Model) highlightedSkipped() (RestoreSkipped, bool) {
	i := m.restore.selectedKey - len(m.restore.previewKeys)
	if i < 0 || i >= len(m.restore.previewSkipped) {
		return RestoreSkipped{}, false
	}
	return m.restore.previewSkipped[i], true
}

// rowCount is the length of the result list: the activated keys, then the
// skipped ones.
func (r RestoreDisplayResult) rowCount() int {
	return len(r.Activated) + len(r.Skipped)
}

// restoreSkippedUnion is the skipped keys the preview showed and any the
// restore reported, each once, in that order.
func restoreSkippedUnion(preview, restored []RestoreSkipped) []RestoreSkipped {
	if len(restored) == 0 {
		return preview
	}
	seen := make(map[string]bool, len(preview))
	out := append([]RestoreSkipped(nil), preview...)
	for _, skipped := range preview {
		seen[skipped.Selector] = true
	}
	for _, skipped := range restored {
		if !seen[skipped.Selector] {
			out = append(out, skipped)
		}
	}
	return out
}

func (m *Model) clampRestoreSelection() {
	if m.restore.selectedBackup >= len(m.restore.backups) {
		m.restore.selectedBackup = len(m.restore.backups) - 1
	}
	if m.restore.selectedBackup < 0 {
		m.restore.selectedBackup = 0
	}
	if m.restore.selectedKey >= m.restorePreviewRowCount() {
		m.restore.selectedKey = m.restorePreviewRowCount() - 1
	}
	if m.restore.selectedKey < 0 {
		m.restore.selectedKey = 0
	}
	m.clampRestorePreviewScroll()
}

func (m Model) restorePreviewVisibleHeight() int {
	if m.height <= 0 {
		return 3
	}
	const moreLines = 2 // the "more above" and "more below" lines
	width := m.popupBodyWidth(restorePreviewPopupWidth)
	chrome := wrappedHeight(m.restorePreviewHeader()+m.restorePreviewFooter(), width) + moreLines
	return max(m.popupContentHeight()-chrome, 1)
}

func (m Model) restoreDisplayContentHeight() int {
	h := m.popupContentHeight()
	if h <= 0 {
		return 20
	}
	return h
}

func restoreDisplayClampOffset(offset, total, visible int) int {
	if visible < 1 {
		visible = 1
	}
	maxOffset := total - visible
	if maxOffset < 0 {
		maxOffset = 0
	}
	if offset > maxOffset {
		return maxOffset
	}
	if offset < 0 {
		return 0
	}
	return offset
}

func (m *Model) clampRestoreDisplayScroll(visibleRows int) {
	if m.restore.displaySelectedKey >= m.restore.result.rowCount() {
		m.restore.displaySelectedKey = m.restore.result.rowCount() - 1
	}
	if m.restore.displaySelectedKey < 0 {
		m.restore.displaySelectedKey = 0
	}
	m.restore.displayScrollOffset = restoreDisplayClampOffset(
		m.restore.displayScrollOffset,
		m.restore.result.rowCount(),
		visibleRows,
	)
	if m.restore.displaySelectedKey < m.restore.displayScrollOffset {
		m.restore.displayScrollOffset = m.restore.displaySelectedKey
	}
	if m.restore.displaySelectedKey >= m.restore.displayScrollOffset+visibleRows {
		m.restore.displayScrollOffset = m.restore.displaySelectedKey - visibleRows + 1
	}
	m.restore.displayScrollOffset = restoreDisplayClampOffset(
		m.restore.displayScrollOffset,
		m.restore.result.rowCount(),
		visibleRows,
	)
}

func (m *Model) clampRestorePreviewScroll() {
	visibleHeight := m.restorePreviewVisibleHeight()
	maxOffset := m.restorePreviewRowCount() - visibleHeight
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.restore.previewScrollOffset > maxOffset {
		m.restore.previewScrollOffset = maxOffset
	}
	if m.restore.previewScrollOffset < 0 {
		m.restore.previewScrollOffset = 0
	}
	if m.restore.selectedKey < m.restore.previewScrollOffset {
		m.restore.previewScrollOffset = m.restore.selectedKey
	}
	if m.restore.selectedKey >= m.restore.previewScrollOffset+visibleHeight {
		m.restore.previewScrollOffset = m.restore.selectedKey - visibleHeight + 1
	}
}

func (m Model) selectedRestoreAddresses() []string {
	if len(m.restore.selected) == 0 {
		return nil
	}
	addresses := make([]string, 0, len(m.restore.selected))
	for _, key := range m.restore.previewKeys {
		if m.restore.selected[key.Address] {
			addresses = append(addresses, key.Address)
		}
	}
	return addresses
}
