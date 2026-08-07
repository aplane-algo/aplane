// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

func (m Model) renderRestoreList() string {
	var sb strings.Builder
	popupWidth := m.popupWidth(90)

	sb.WriteString(titleStyle.Render("Restore Backup"))
	sb.WriteString("\n")
	if dir := m.backupDirectoryLabel(); dir != "" {
		sb.WriteString(subtitleStyle.Render("Backup Directory: " + dir))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString("\n")
	}

	if !m.restore.backupsLoaded {
		sb.WriteString(subtitleStyle.Render("Loading backup archives..."))
		sb.WriteString("\n")
		return m.renderPopup(popupWidth, sb.String())
	}

	if len(m.restore.backups) == 0 {
		sb.WriteString(subtitleStyle.Render("No signer-managed backup archives found."))
		return m.renderPopup(popupWidth, sb.String())
	}

	sb.WriteString(subtitleStyle.Render("Select a backup archive to preview."))
	sb.WriteString("\n\n")
	for i, backupInfo := range m.restore.backups {
		prefix := "  "
		if i == m.restore.selectedBackup {
			prefix = "> "
		}
		line := fmt.Sprintf("%s%-34s  %s  %s",
			prefix,
			restoreBackupName(backupInfo),
			formatRestoreTime(backupInfo.CreatedAt),
			formatRestoreSize(backupInfo.Size),
		)
		if i == m.restore.selectedBackup {
			sb.WriteString(selectedStyle.Render(line))
		} else {
			sb.WriteString(normalStyle.Render(line))
		}
		sb.WriteString("\n")
	}

	return m.renderPopup(popupWidth, sb.String())
}

func (m Model) backupDirectoryLabel() string {
	if strings.TrimSpace(m.dataDir) == "" {
		return ""
	}
	dir := filepath.Join(m.dataDir, "backups")
	if !strings.HasSuffix(dir, string(filepath.Separator)) {
		dir += string(filepath.Separator)
	}
	return dir
}

func (m Model) renderRestorePassphrase() string {
	var sb strings.Builder

	if m.restore.replaceExisting {
		sb.WriteString(titleStyle.Render("Confirm Credential Replacement"))
	} else {
		sb.WriteString(titleStyle.Render("Unlock Backup Preview"))
	}
	sb.WriteString("\n\n")
	sb.WriteString("Archive:\n")
	sb.WriteString(restoreArchiveLabel(m.restore.archivePath))
	sb.WriteString("\n\n")
	if m.restore.replaceExisting {
		sb.WriteString(errorStyle.Render("The following destination credentials will be replaced:"))
		sb.WriteString("\n")
		for _, conflict := range m.restore.replaceConflicts {
			sb.WriteString("  ")
			sb.WriteString(conflict.Selector)
			if conflict.KeyType != "" {
				sb.WriteString(" [")
				sb.WriteString(conflict.KeyType)
				sb.WriteString("]")
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Re-enter the export passphrase and press Enter to authorize replacement."))
	} else {
		sb.WriteString(subtitleStyle.Render("Enter the backup export passphrase before metadata is shown."))
	}
	sb.WriteString("\n\n")

	masked := strings.Repeat("*", len(m.restore.passphrase))
	if masked == "" {
		masked = " "
	}
	sb.WriteString(inputActiveStyle.Width(44).Render(masked))
	sb.WriteString("\n")

	if m.restore.previewing {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Previewing backup archive..."))
		sb.WriteString("\n")
	}

	if m.restore.passphraseError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(m.restore.passphraseError))
		sb.WriteString("\n")
	}

	return m.renderPopup(90, sb.String())
}

func (m Model) renderRestorePreview() string {
	var sb strings.Builder
	popupWidth := m.popupWidth(110)
	rowWidth := restorePreviewRowWidth(popupWidth)

	sb.WriteString(titleStyle.Render("Restore Preview"))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Archive:   %s\n", restoreArchiveLabel(m.restore.archivePath)))
	sb.WriteString(fmt.Sprintf("Selected: %d\n", m.selectedRestoreCount()))
	sb.WriteString("\n")

	if len(m.restore.previewKeys) == 0 {
		sb.WriteString(subtitleStyle.Render("No restorable keys were found in this archive."))
		sb.WriteString("\n")
	} else {
		visibleHeight := m.restorePreviewVisibleHeight()
		scrollOffset := m.restore.previewScrollOffset
		if scrollOffset >= len(m.restore.previewKeys) {
			scrollOffset = 0
		}

		sb.WriteString(scrollMoreAboveLine(scrollOffset))
		sb.WriteString("\n")

		endIdx := scrollOffset + visibleHeight
		if endIdx > len(m.restore.previewKeys) {
			endIdx = len(m.restore.previewKeys)
		}

		for i := scrollOffset; i < endIdx; i++ {
			key := m.restore.previewKeys[i]
			prefix := "  "
			if i == m.restore.selectedKey {
				prefix = "> "
			}
			line := restorePreviewKeyLine(m, key, prefix, rowWidth)
			if key.Error != "" {
				sb.WriteString(errorStyle.Render(line))
			} else if key.AlreadyExists {
				sb.WriteString(helpStyle.Render(line))
			} else if i == m.restore.selectedKey {
				sb.WriteString(selectedStyle.Render(line))
			} else {
				sb.WriteString(normalStyle.Render(line))
			}
			sb.WriteString("\n")
		}

		sb.WriteString(scrollMoreBelowLine(len(m.restore.previewKeys) - endIdx))
		sb.WriteString("\n")

		sb.WriteString(fmt.Sprintf("  Total: %d keys\n", len(m.restore.previewKeys)))
	}

	if len(m.restore.previewErrors) > 0 {
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render("Preview warnings:"))
		sb.WriteString("\n")
		for _, restoreErr := range m.restore.previewErrors {
			sb.WriteString("  ")
			if restoreErr.Address != "" {
				sb.WriteString(restoreErr.Address)
				sb.WriteString(": ")
			}
			sb.WriteString(restoreErr.Error)
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(restoreActionButton(
		"RESTORE",
		m.restore.previewFocus == restoreFocusAction,
		m.selectedRestoreCount() > 0,
	))
	sb.WriteString("\n")

	if m.restore.previewError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(m.restore.previewError))
		sb.WriteString("\n")
	}

	return m.renderPopup(popupWidth, sb.String())
}

// restoreActionButton renders one commit button. ready styles a button whose
// preconditions are met; an unready button is still focusable so activating it
// can explain what is missing.
func restoreActionButton(label string, focused, ready bool) string {
	if !focused {
		return buttonInactiveStyle.Render("  " + label)
	}
	if !ready {
		return buttonInactiveStyle.Render("> " + label)
	}
	return buttonActiveStyle.Render("> " + label)
}

func (m Model) renderRestoring() string {
	var sb strings.Builder
	title := m.restore.progressLabel
	if title == "" {
		title = "Working"
	}
	sb.WriteString(titleStyle.Render(title))
	sb.WriteString("\n\n")
	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")
	return m.renderPopup(70, sb.String())
}

func (m Model) renderRestoreDisplay() string {
	result := m.restore.result
	popupWidth := m.popupWidth(110)
	rowWidth := restorePreviewRowWidth(popupWidth)
	contentHeight := m.restoreDisplayContentHeight()

	lines := make([]string, 0, contentHeight)
	if result.Success {
		lines = append(lines, titleStyle.Render("Restore Complete"))
	} else {
		lines = append(lines, titleStyle.Render("Restore Finished With Errors"))
	}
	lines = append(lines, "")
	if result.ArchivePath != "" {
		lines = append(lines, fmt.Sprintf("Archive: %s", restoreArchiveLabel(result.ArchivePath)))
	}
	lines = append(lines,
		fmt.Sprintf("Activated: %d", len(result.Activated)),
	)

	if result.Error != "" {
		lines = append(lines, "", errorStyle.Render(result.Error))
	}
	lines = append(lines, "")

	if len(result.Activated) > 0 {
		overhead := 5 // header, above indicator, below indicator, total, spacer
		visibleRows := contentHeight - len(lines) - overhead
		if visibleRows < 1 {
			visibleRows = 1
		}
		displayModel := m
		displayModel.clampRestoreDisplayScroll(visibleRows)
		scrollOffset := displayModel.restore.displayScrollOffset
		endIdx := scrollOffset + visibleRows
		if endIdx > len(result.Activated) {
			endIdx = len(result.Activated)
		}

		lines = append(lines, statusUnlockedStyle.Render("Restored keys:"))
		if above := scrollMoreAboveLine(scrollOffset); above != "" {
			lines = append(lines, above)
		}
		for i := scrollOffset; i < endIdx; i++ {
			prefix := "  "
			if i == displayModel.restore.displaySelectedKey {
				prefix = "> "
			}
			line := restoreDisplayKeyLine(result.Activated[i], prefix, rowWidth)
			if i == displayModel.restore.displaySelectedKey {
				lines = append(lines, selectedStyle.Render(line))
			} else {
				lines = append(lines, normalStyle.Render(line))
			}
		}
		if below := scrollMoreBelowLine(len(result.Activated) - endIdx); below != "" {
			lines = append(lines, below)
		}
		lines = append(lines, fmt.Sprintf("  Total: %d activated keys", len(result.Activated)))
		lines = append(lines, "")
	}

	if len(lines) > contentHeight {
		lines = lines[:contentHeight]
	}
	return m.renderPopup(popupWidth, strings.Join(lines, "\n"))
}

func restoreDisplayKeyLine(key RestoreKeyInfo, prefix string, maxWidth int) string {
	keyType := "[" + displayKeyType(key.KeyType) + "]"
	suffix := "  " + keyType
	addressWidth := keyAddressWidth(maxWidth, prefix, "", suffix)
	return fmt.Sprintf("%s%s%s", prefix, restorePreviewAddress(key, addressWidth), suffix)
}

func restoreBackupName(info BackupInfo) string {
	if info.FileName != "" {
		return info.FileName
	}
	return filepath.Base(info.Path)
}

func restoreArchiveLabel(path string) string {
	if path == "" {
		return "(none)"
	}
	return filepath.Base(path)
}

func formatRestoreTime(unix int64) string {
	if unix <= 0 {
		return "unknown"
	}
	return time.Unix(unix, 0).Local().Format("2006-01-02 15:04")
}

func formatRestoreSize(size int64) string {
	if size <= 0 {
		return "0 B"
	}
	const unit = int64(1024)
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := unit, 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func restoreSelectionMark(m Model, key RestoreKeyInfo) string {
	if m.restore.selected[key.Address] {
		return "* "
	}
	return "  "
}

func restorePreviewRowWidth(popupWidth int) int {
	// popupStyle has a border plus horizontal padding. Keep rows inside that chrome.
	width := popupWidth - 6
	if width < 20 {
		return 20
	}
	return width
}

func restorePreviewKeyLine(m Model, key RestoreKeyInfo, prefix string, maxWidth int) string {
	mark := restoreSelectionMark(m, key)
	keyType := "[" + displayKeyType(key.KeyType) + "]"
	suffix := "  " + keyType + restorePreviewSuffix(key)

	addressWidth := keyAddressWidth(maxWidth, prefix, mark, suffix)
	if addressWidth < keyAddressShortWidth && len(suffix) > len("  "+keyType) {
		extraBudget := maxWidth - len(prefix) - len(mark) - len("  "+keyType) - keyAddressShortWidth
		extra := ellipsize(restorePreviewSuffix(key), extraBudget)
		suffix = "  " + keyType + extra
		addressWidth = keyAddressWidth(maxWidth, prefix, mark, suffix)
	}

	return fmt.Sprintf("%s%s%s%s",
		prefix,
		mark,
		restorePreviewAddress(key, addressWidth),
		suffix,
	)
}

func restorePreviewSuffix(key RestoreKeyInfo) string {
	var suffix string
	if key.AlreadyExists {
		// Informational: replacement still requires explicit confirmation.
		suffix += "  exists"
	}
	if key.Error != "" {
		suffix += "  " + key.Error
	}
	return suffix
}

func restorePreviewAddress(key RestoreKeyInfo, width int) string {
	return formatKeyAddress(key.Address, key.KeyType, width, !key.AlreadyExists)
}
