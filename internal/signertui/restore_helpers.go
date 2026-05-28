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
	zeroBytes(m.restorePassphrase)
	m.restorePassphrase = nil
}

func (m *Model) resetRestoreFlow(clearBackups bool) {
	m.clearRestorePassphrase()
	if clearBackups {
		m.restoreBackups = nil
		m.restoreBackupsLoaded = false
		m.selectedBackup = 0
		m.restoreBackupScrollOffset = 0
	}
	m.restoreArchivePath = ""
	m.restorePassphraseError = ""
	m.restorePreviewing = false
	m.restorePreviewKeys = nil
	m.restorePreviewErrors = nil
	m.restoreSelected = nil
	m.restoreSelectedKey = 0
	m.restorePreviewScrollOffset = 0
	m.restorePreviewError = ""
	m.restoreOverwrite = false
	m.restoreDisplaySelectedKey = 0
	m.restoreDisplayScrollOffset = 0
	m.restoreResult = RestoreBackupResultMessage{}
}

func (m Model) currentRestoreBackup() (BackupInfo, bool) {
	if len(m.restoreBackups) == 0 || m.selectedBackup < 0 || m.selectedBackup >= len(m.restoreBackups) {
		return BackupInfo{}, false
	}
	return m.restoreBackups[m.selectedBackup], true
}

func (m Model) restoreKeySelectable(key RestoreKeyInfo) bool {
	if key.Error != "" || key.Address == "" {
		return false
	}
	return !key.AlreadyExists || m.restoreOverwrite
}

func (m *Model) initializeRestoreSelection() {
	m.restoreSelected = make(map[string]bool)
	for _, key := range m.restorePreviewKeys {
		if key.Error == "" && key.Address != "" && !key.AlreadyExists {
			m.restoreSelected[key.Address] = true
		}
	}
	m.clampRestoreSelection()
}

func (m *Model) clampRestoreSelection() {
	if m.selectedBackup >= len(m.restoreBackups) {
		m.selectedBackup = len(m.restoreBackups) - 1
	}
	if m.selectedBackup < 0 {
		m.selectedBackup = 0
	}
	if m.restoreBackupScrollOffset > m.selectedBackup {
		m.restoreBackupScrollOffset = m.selectedBackup
	}
	if m.restoreSelectedKey >= len(m.restorePreviewKeys) {
		m.restoreSelectedKey = len(m.restorePreviewKeys) - 1
	}
	if m.restoreSelectedKey < 0 {
		m.restoreSelectedKey = 0
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
	if m.restoreDisplaySelectedKey >= len(m.restoreResult.Restored) {
		m.restoreDisplaySelectedKey = len(m.restoreResult.Restored) - 1
	}
	if m.restoreDisplaySelectedKey < 0 {
		m.restoreDisplaySelectedKey = 0
	}
	m.restoreDisplayScrollOffset = restoreDisplayClampOffset(
		m.restoreDisplayScrollOffset,
		len(m.restoreResult.Restored),
		visibleRows,
	)
	if m.restoreDisplaySelectedKey < m.restoreDisplayScrollOffset {
		m.restoreDisplayScrollOffset = m.restoreDisplaySelectedKey
	}
	if m.restoreDisplaySelectedKey >= m.restoreDisplayScrollOffset+visibleRows {
		m.restoreDisplayScrollOffset = m.restoreDisplaySelectedKey - visibleRows + 1
	}
	m.restoreDisplayScrollOffset = restoreDisplayClampOffset(
		m.restoreDisplayScrollOffset,
		len(m.restoreResult.Restored),
		visibleRows,
	)
}

func (m *Model) clampRestorePreviewScroll() {
	visibleHeight := m.restorePreviewVisibleHeight()
	maxOffset := len(m.restorePreviewKeys) - visibleHeight
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.restorePreviewScrollOffset > maxOffset {
		m.restorePreviewScrollOffset = maxOffset
	}
	if m.restorePreviewScrollOffset < 0 {
		m.restorePreviewScrollOffset = 0
	}
	if m.restoreSelectedKey < m.restorePreviewScrollOffset {
		m.restorePreviewScrollOffset = m.restoreSelectedKey
	}
	if m.restoreSelectedKey >= m.restorePreviewScrollOffset+visibleHeight {
		m.restorePreviewScrollOffset = m.restoreSelectedKey - visibleHeight + 1
	}
	if m.restorePreviewScrollOffset < 0 {
		m.restorePreviewScrollOffset = 0
	}
}

func (m Model) selectedRestoreAddresses() []string {
	if len(m.restoreSelected) == 0 {
		return nil
	}
	addresses := make([]string, 0, len(m.restoreSelected))
	for _, key := range m.restorePreviewKeys {
		if m.restoreSelected[key.Address] {
			addresses = append(addresses, key.Address)
		}
	}
	return addresses
}

func (m Model) selectedRestoreCount() int {
	count := 0
	for _, key := range m.restorePreviewKeys {
		if m.restoreSelected[key.Address] {
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
