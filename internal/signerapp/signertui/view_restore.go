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
			sb.WriteString(terminalSafe(conflict.Selector))
			if conflict.KeyType != "" {
				sb.WriteString(" [")
				sb.WriteString(terminalSafe(conflict.KeyType))
				sb.WriteString("]")
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Re-enter the export passphrase and press Enter to authorize replacement."))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString("Backup passphrase\n")
	}

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
		sb.WriteString(errorStyle.Render(terminalSafeLines(m.restore.passphraseError)))
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
)

func (m Model) renderRestorePreview() string {
	var sb strings.Builder
	popupWidth := m.popupWidth(restorePreviewPopupWidth)
	rowWidth := restorePreviewRowWidth(popupWidth)
	m.clampRestorePreviewScroll()

	sb.WriteString(m.restorePreviewHeader())
	rows := m.restorePreviewRowCount()
	if rows == 0 {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("No restorable keys were found in this archive."))
		sb.WriteString("\n")
	} else {
		addressWidth := restorePreviewAddressWidth(m.restore.previewKeys, rowWidth)
		scrollOffset := m.restore.previewScrollOffset

		sb.WriteString(scrollMoreAboveLine(scrollOffset))
		sb.WriteString("\n")

		endIdx := min(scrollOffset+m.restorePreviewVisibleHeight(), rows)
		for i := scrollOffset; i < endIdx; i++ {
			prefix := "  "
			if i == m.restore.selectedKey {
				prefix = "> "
			}
			if i >= len(m.restore.previewKeys) {
				skipped := m.restore.previewSkipped[i-len(m.restore.previewKeys)]
				sb.WriteString(errorStyle.Render(restoreSkippedLine(skipped, prefix+"  ", addressWidth, rowWidth)))
				sb.WriteString("\n")
				continue
			}
			key := m.restore.previewKeys[i]
			line := restorePreviewKeyLine(m, key, prefix, addressWidth, rowWidth)
			if key.AlreadyExists {
				sb.WriteString(helpStyle.Render(line))
			} else if i == m.restore.selectedKey {
				sb.WriteString(selectedStyle.Render(line))
			} else {
				sb.WriteString(normalStyle.Render(line))
			}
			sb.WriteString("\n")
		}

		sb.WriteString(scrollMoreBelowLine(rows - endIdx))
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
	sb.WriteString(fmt.Sprintf("Selected: %d of %d", len(m.selectedRestoreAddresses()), len(m.restore.previewKeys)))
	if skipped := len(m.restore.previewSkipped); skipped > 0 {
		sb.WriteString("  " + skippedCountText(skipped, m.restore.previewSkipOmitted))
	}
	sb.WriteString("\n")
	return sb.String()
}

// skippedCountText counts skipped keys, saying when only some are listed.
func skippedCountText(listed, omitted int) string {
	if omitted == 0 {
		return fmt.Sprintf("Skipped: %d", listed)
	}
	return fmt.Sprintf("Skipped: %d (%d listed)", listed+omitted, listed)
}

// restoreSkippedReasonRunes bounds the reason the preview footer shows for
// the highlighted skipped key, so the footer cannot crowd out the list.
const restoreSkippedReasonRunes = 200

func (m Model) restorePreviewFooter() string {
	var sb strings.Builder
	if skipped, ok := m.highlightedSkipped(); ok {
		width := m.popupBodyWidth(restorePreviewPopupWidth)
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render(wrapPlainText(
			"Skipped: "+ellipsize(terminalSafe(skipped.Reason), restoreSkippedReasonRunes), width)))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(restoreActionButton(
		"RESTORE",
		m.restore.previewFocus == restoreFocusAction,
		len(m.selectedRestoreAddresses()) > 0,
	))
	sb.WriteString("\n")

	if m.restore.previewError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(terminalSafeLines(m.restore.previewError)))
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

// restoreDisplayListOverhead is the lines the result list takes beside its
// rows: its label, the more-above and more-below lines, its total and a
// spacer.
const restoreDisplayListOverhead = 5

// renderRestoreDisplay lays the result screen out one screen line per
// element of lines, wrapping text before it counts it, so the list is given
// exactly the rows the window has left and the popup's border and the total
// stay on screen.
func (m Model) renderRestoreDisplay() string {
	result := m.restore.result
	popupWidth := m.popupWidth(110)
	rowWidth := restorePreviewRowWidth(popupWidth)
	width := m.popupBodyWidth(110)
	contentHeight := m.restoreDisplayContentHeight()

	lines := make([]string, 0, contentHeight)
	if result.Success {
		lines = append(lines, titleStyle.Render("Restore Complete"))
	} else {
		lines = append(lines, titleStyle.Render("Restore Finished With Errors"))
	}
	lines = append(lines, "")
	if result.ArchivePath != "" {
		const label = "Archive: "
		lines = append(lines, label+ellipsizeMiddle(restoreArchiveLabel(result.ArchivePath), max(width-len(label), 1)))
	}
	lines = append(lines,
		fmt.Sprintf("Activated: %d", len(result.Activated)),
	)
	if len(result.Skipped) > 0 {
		lines = append(lines, errorStyle.Render(ellipsize(skippedCountText(len(result.Skipped), result.SkippedOmitted)+" (cannot be restored on this node)", width)))
	}

	listRoom := 0
	if result.rowCount() > 0 {
		listRoom = restoreDisplayListOverhead + 1 // and at least one row
	}
	if result.Error != "" {
		// The error gives way to the list: two blank lines frame it.
		budget := max(contentHeight-len(lines)-2-listRoom, 1)
		lines = append(lines, "")
		for _, line := range restoreErrorLines(result.Error, width, budget) {
			lines = append(lines, errorStyle.Render(line))
		}
	}
	lines = append(lines, "")

	if listRoom > 0 {
		lines = append(lines, m.restoreDisplayList(rowWidth, max(contentHeight-len(lines)-restoreDisplayListOverhead, 1))...)
	}

	if len(lines) > contentHeight {
		lines = lines[:contentHeight]
	}
	return m.renderPopup(popupWidth, strings.Join(lines, "\n"))
}

// restoreErrorLines wraps an error to width and keeps at most budget lines,
// marking a cut.
func restoreErrorLines(text string, width, budget int) []string {
	lines := strings.Split(wrapPlainText(terminalSafeLines(text), width), "\n")
	if len(lines) <= budget {
		return lines
	}
	lines = lines[:budget]
	lines[budget-1] = ellipsize(strings.TrimRight(lines[budget-1], " ")+" …", width)
	return lines
}

// restoreDisplayList is the result screen's scrolling list: the activated
// keys, then the skipped ones, under a label and over their total.
func (m Model) restoreDisplayList(rowWidth, visibleRows int) []string {
	result := m.restore.result
	rows := result.rowCount()
	m.clampRestoreDisplayScroll(visibleRows)
	scrollOffset := m.restore.displayScrollOffset
	endIdx := min(scrollOffset+visibleRows, rows)

	label := "Restored keys:"
	if len(result.Activated) == 0 {
		label = "Skipped keys:"
	}
	lines := []string{statusUnlockedStyle.Render(label)}
	if above := scrollMoreAboveLine(scrollOffset); above != "" {
		lines = append(lines, above)
	}
	for i := scrollOffset; i < endIdx; i++ {
		lines = append(lines, restoreDisplayRow(result, i, i == m.restore.displaySelectedKey, rowWidth))
	}
	if below := scrollMoreBelowLine(rows - endIdx); below != "" {
		lines = append(lines, below)
	}
	total := fmt.Sprintf("  Total: %d activated keys", len(result.Activated))
	if len(result.Skipped) > 0 {
		total += fmt.Sprintf(", %d skipped", len(result.Skipped)+result.SkippedOmitted)
	}
	return append(lines, total, "")
}

// restoreDisplayRow renders row i of the result list.
func restoreDisplayRow(result RestoreDisplayResult, i int, selected bool, rowWidth int) string {
	prefix := "  "
	if selected {
		prefix = "> "
	}
	if i >= len(result.Activated) {
		return errorStyle.Render(restoreSkippedLine(result.Skipped[i-len(result.Activated)], prefix, keyAddressShortWidth, rowWidth))
	}
	line := restoreDisplayKeyLine(result.Activated[i], prefix, rowWidth)
	if selected {
		return selectedStyle.Render(line)
	}
	return normalStyle.Render(line)
}

func restoreDisplayKeyLine(key RestoreKeyInfo, prefix string, maxWidth int) string {
	keyType := "[" + displayKeyType(key.KeyType) + "]"
	suffix := "  " + keyType
	if key.HasPolicy {
		suffix += "  policy"
	}
	addressWidth := keyAddressWidth(maxWidth, prefix, suffix)
	return fmt.Sprintf("%s%s%s", prefix, restorePreviewAddress(key, addressWidth), suffix)
}

// restoreArchiveLabel is the archive's file name, which whoever made or
// renamed an imported archive chose.
func restoreArchiveLabel(path string) string {
	if path == "" {
		return "(none)"
	}
	return terminalSafe(filepath.Base(path))
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
	keyType := "[" + ellipsizeMiddle(displayKeyType(key.KeyType), max(room-2, 0)) + "]"
	address := restorePreviewAddress(key, addressWidth)
	addressPad := max(addressWidth-utf8.RuneCountInString(ellipsizeMiddle(terminalSafe(key.Address), addressWidth)), 0)
	flagPad := max(room-len(keyType), 0)

	return prefix + restoreSelectionMark(m, key) + address + strings.Repeat(" ", addressPad) +
		"  " + keyType + strings.Repeat(" ", flagPad) + flags
}

// restoreSkippedLine lays out a key the restore skips: its address, then the
// reason in what the row has left. lead is the row's cursor and selection
// columns.
func restoreSkippedLine(skipped RestoreSkipped, lead string, addressWidth, rowWidth int) string {
	address := ellipsizeMiddle(terminalSafe(skipped.Selector), addressWidth)
	addressPad := max(addressWidth-utf8.RuneCountInString(address), 0)
	room := max(rowWidth-utf8.RuneCountInString(lead)-addressWidth-restoreColumnGap, 0)
	return lead + address + strings.Repeat(" ", addressPad) + "  " + ellipsize("skipped: "+terminalSafe(skipped.Reason), room)
}

func restoreKeyTypeWidth(key RestoreKeyInfo) int {
	return len("[" + displayKeyType(key.KeyType) + "]")
}

// restorePreviewFlags is the short, fixed vocabulary at the end of a key row.
func restorePreviewFlags(key RestoreKeyInfo) string {
	var suffix string
	if key.AlreadyExists {
		// The node holds a key at this address. Preview does not compare
		// the two; restore's conflict check decides, and replacement still
		// requires explicit confirmation.
		suffix += "  exists"
	}
	if key.HasPolicy {
		suffix += "  +policy"
	}
	return suffix
}

// restorePreviewAddress shows a key's address, which an archive entry
// supplies.
func restorePreviewAddress(key RestoreKeyInfo, width int) string {
	return formatKeyAddress(terminalSafe(key.Address), key.KeyType, width, !key.AlreadyExists)
}
