// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

func cloneBytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func (m *Model) clearRestorePassphrase() {
	zeroBytes(m.restore.passphrase)
	m.restore.passphrase = nil
}

func (m *Model) resetRestoreFlow(clearBackups bool) {
	m.clearRestorePassphrase()
	if clearBackups {
		m.restore.backups = nil
		m.restore.backupsLoaded = false
		m.restore.selectedBackup = 0
		m.restore.backupScrollOffset = 0
	}
	m.restore.archivePath = ""
	m.restore.passphraseError = ""
	m.restore.previewing = false
	m.restore.previewKeys = nil
	m.restore.previewErrors = nil
	m.restore.selected = nil
	m.restore.selectedKey = 0
	m.restore.previewScrollOffset = 0
	m.restore.previewError = ""
	m.restore.overwrite = false
	m.restore.restoreID = ""
	m.restore.review = ReviewRecoveredResultMessage{}
	m.restore.previewFocus = restoreFocusList
	m.restore.unattendedAcknowledged = false
	m.restore.reviewFocus = restoreFocusList
	m.restore.displaySelectedKey = 0
	m.restore.displayScrollOffset = 0
	m.restore.result = RestoreDisplayResult{}
}

func (m Model) currentRestoreBackup() (BackupInfo, bool) {
	if len(m.restore.backups) == 0 || m.restore.selectedBackup < 0 || m.restore.selectedBackup >= len(m.restore.backups) {
		return BackupInfo{}, false
	}
	return m.restore.backups[m.restore.selectedBackup], true
}

func (m Model) restoreKeySelectable(key RestoreKeyInfo) bool {
	if key.Error != "" || key.Address == "" {
		return false
	}
	return !key.AlreadyExists || m.restore.overwrite
}

func (m *Model) initializeRestoreSelection() {
	m.restore.selected = make(map[string]bool)
	for _, key := range m.restore.previewKeys {
		if key.Error == "" && key.Address != "" && !key.AlreadyExists {
			m.restore.selected[key.Address] = true
		}
	}
	m.clampRestoreSelection()
}

func (m *Model) clampRestoreSelection() {
	if m.restore.selectedBackup >= len(m.restore.backups) {
		m.restore.selectedBackup = len(m.restore.backups) - 1
	}
	if m.restore.selectedBackup < 0 {
		m.restore.selectedBackup = 0
	}
	if m.restore.backupScrollOffset > m.restore.selectedBackup {
		m.restore.backupScrollOffset = m.restore.selectedBackup
	}
	if m.restore.selectedKey >= len(m.restore.previewKeys) {
		m.restore.selectedKey = len(m.restore.previewKeys) - 1
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
	h := m.height - 14
	if h < 1 {
		return 1
	}
	return h
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
	if m.restore.displaySelectedKey >= len(m.restore.result.Activated) {
		m.restore.displaySelectedKey = len(m.restore.result.Activated) - 1
	}
	if m.restore.displaySelectedKey < 0 {
		m.restore.displaySelectedKey = 0
	}
	m.restore.displayScrollOffset = restoreDisplayClampOffset(
		m.restore.displayScrollOffset,
		len(m.restore.result.Activated),
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
		len(m.restore.result.Activated),
		visibleRows,
	)
}

func (m *Model) clampRestorePreviewScroll() {
	visibleHeight := m.restorePreviewVisibleHeight()
	maxOffset := len(m.restore.previewKeys) - visibleHeight
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
	if m.restore.previewScrollOffset < 0 {
		m.restore.previewScrollOffset = 0
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

func (m Model) selectedRestoreCount() int {
	count := 0
	for _, key := range m.restore.previewKeys {
		if m.restore.selected[key.Address] {
			count++
		}
	}
	return count
}

func firstRestoreError(errors []RestoreError) string {
	for _, restoreErr := range errors {
		if restoreErr.Error != "" {
			return restoreErr.Error
		}
	}
	return ""
}
