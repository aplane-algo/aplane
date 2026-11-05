// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

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

const (
	restorePreviewPopupWidth = 110
	restoreRowLeadWidth      = 4 // cursor and selection mark
	restoreColumnGap         = 2
	// restoreAddressMinWidth is 7 leading chars + "..." + 7 trailing chars.
	restoreAddressMinWidth = 17
	// restoreErrorKeyTypeWidth is what a key type keeps beside an error.
	restoreErrorKeyTypeWidth = 12
)

func (m Model) renderRestorePreview() string {
	var sb strings.Builder
	popupWidth := m.popupWidth(restorePreviewPopupWidth)
	rowWidth := restorePreviewRowWidth(popupWidth)
	m.clampRestorePreviewScroll()

	sb.WriteString(m.restorePreviewHeader())
	if len(m.restore.previewKeys) == 0 {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("No restorable keys were found in this archive."))
		sb.WriteString("\n")
	} else {
		addressWidth := restorePreviewAddressWidth(m.restore.previewKeys, rowWidth)
		scrollOffset := m.restore.previewScrollOffset

		sb.WriteString(scrollMoreAboveLine(scrollOffset))
		sb.WriteString("\n")

		endIdx := min(scrollOffset+m.restorePreviewVisibleHeight(), len(m.restore.previewKeys))
		for i := scrollOffset; i < endIdx; i++ {
			key := m.restore.previewKeys[i]
			prefix := "  "
			if i == m.restore.selectedKey {
				prefix = "> "
			}
			line := restorePreviewKeyLine(m, key, prefix, addressWidth, rowWidth)
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
	}
	sb.WriteString(m.restorePreviewFooter())

	return m.renderPopup(popupWidth, sb.String())
}

// restorePreviewHeader and restorePreviewFooter are the lines around the key
// list; restorePreviewVisibleHeight gives the list what they leave.
func (m Model) restorePreviewHeader() string {
	var sb strings.Builder
	popupWidth := m.popupWidth(restorePreviewPopupWidth)
	sb.WriteString(titleStyle.Render("Backup Contents"))
	sb.WriteString("\n")
	sb.WriteString(m.renderBackupViewHeader(popupWidth))
	sb.WriteString(fmt.Sprintf("Selected: %d of %d (\"present\": this node holds a key at that address)\n",
		m.selectedRestoreCount(), len(m.restore.previewKeys)))
	return sb.String()
}

func (m Model) restorePreviewFooter() string {
	var sb strings.Builder
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
	return sb.String()
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
	if key.HasPolicy {
		suffix += "  policy"
	}
	addressWidth := keyAddressWidth(maxWidth, prefix, "", suffix)
	return fmt.Sprintf("%s%s%s", prefix, restorePreviewAddress(key, addressWidth), suffix)
}

func restoreArchiveLabel(path string) string {
	if path == "" {
		return "(none)"
	}
	return filepath.Base(path)
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

// restorePreviewAddressWidth is the address column for the whole list, so key
// types start in the same place on every row. It gives way, down to
// restoreAddressMinWidth, to the row that needs the most room.
func restorePreviewAddressWidth(keys []RestoreKeyInfo, rowWidth int) int {
	width := keyAddressShortWidth
	for _, key := range keys {
		room := rowWidth - restoreRowLeadWidth - restoreColumnGap - restoreKeyTypeWidth(key) - len(restorePreviewFlags(key))
		width = min(width, max(room, restoreAddressMinWidth))
	}
	return width
}

// restorePreviewKeyLine lays out one key row with its flags against the right
// edge. The flags are what a restore decision turns on, so they stay whole and
// the key type gives way when a row is still too long.
func restorePreviewKeyLine(m Model, key RestoreKeyInfo, prefix string, addressWidth, rowWidth int) string {
	flags := restorePreviewFlags(key)
	room := rowWidth - restoreRowLeadWidth - addressWidth - restoreColumnGap - len(flags)
	if key.Error != "" {
		// An error is free text: it takes what the key type does not need.
		errorWidth := max(room-min(restoreKeyTypeWidth(key), restoreErrorKeyTypeWidth)-restoreColumnGap, 0)
		flags += "  " + ellipsize(key.Error, errorWidth)
		room = rowWidth - restoreRowLeadWidth - addressWidth - restoreColumnGap - utf8.RuneCountInString(flags)
	}
	keyType := "[" + ellipsizeMiddle(displayKeyType(key.KeyType), max(room-2, 0)) + "]"
	address := restorePreviewAddress(key, addressWidth)
	addressPad := max(addressWidth-utf8.RuneCountInString(ellipsizeMiddle(key.Address, addressWidth)), 0)
	flagPad := max(room-len(keyType), 0)

	return prefix + restoreSelectionMark(m, key) + address + strings.Repeat(" ", addressPad) +
		"  " + keyType + strings.Repeat(" ", flagPad) + flags
}

func restoreKeyTypeWidth(key RestoreKeyInfo) int {
	return len("[" + displayKeyType(key.KeyType) + "]")
}

// restorePreviewFlags is the short, fixed vocabulary at the end of a key row.
func restorePreviewFlags(key RestoreKeyInfo) string {
	var suffix string
	if key.StageHint != nil {
		suffix += fmt.Sprintf("  hint %d", *key.StageHint)
	}
	if key.AlreadyExists {
		// The node holds a key at this address. Preview does not compare
		// the two; restore's conflict check decides, and replacement still
		// requires explicit confirmation.
		suffix += "  present"
	}
	if key.HasPolicy {
		suffix += "  +policy"
	}
	return suffix
}

func restorePreviewAddress(key RestoreKeyInfo, width int) string {
	return formatKeyAddress(key.Address, key.KeyType, width, !key.AlreadyExists)
}
