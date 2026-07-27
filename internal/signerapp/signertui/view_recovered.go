// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
)

// recoveredVisibleHeight bounds the batch rows to the popup body.
func (m Model) recoveredVisibleHeight() int {
	height := m.height - 14
	if height < 3 {
		height = 3
	}
	return height
}

func (m Model) renderRecoveredList() string {
	var sb strings.Builder
	popupWidth := m.popupWidth(96)

	if m.signerState == signerRuntimeRecovery {
		sb.WriteString(titleStyle.Render("Recovery Required"))
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render("Signing is disabled: an incomplete activation must be rolled back or resumed."))
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Rollback (x) restores the exact pre-activation state and is the default resolution."))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString(titleStyle.Render("Recovered Batches"))
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render("Reopening a batch for review needs no export passphrase."))
		sb.WriteString("\n\n")
	}

	switch {
	case !m.restore.recoveredLoaded:
		sb.WriteString(subtitleStyle.Render("Loading recovered batches..."))
		sb.WriteString("\n")
	case len(m.restore.recovered) == 0:
		sb.WriteString(subtitleStyle.Render("No recovered batches."))
		sb.WriteString("\n")
	default:
		visible := m.recoveredVisibleHeight()
		start := m.restore.recoveredScrollOffset
		if start > 0 {
			sb.WriteString(scrollMoreAboveLine(start))
			sb.WriteString("\n")
		}
		end := start + visible
		if end > len(m.restore.recovered) {
			end = len(m.restore.recovered)
		}
		for i := start; i < end; i++ {
			batch := m.restore.recovered[i]
			prefix := "  "
			if i == m.restore.selectedRecovered {
				prefix = "> "
			}
			line := fmt.Sprintf("%s%s  %s  %2d entr%s",
				prefix,
				batch.RestoreID,
				formatRestoreTime(batch.CreatedAt),
				batch.EntryCount,
				pluralSuffixIesY(batch.EntryCount),
			)
			if i == m.restore.selectedRecovered {
				sb.WriteString(selectedStyle.Render(line))
			} else {
				sb.WriteString(normalStyle.Render(line))
			}
			sb.WriteString("\n")
		}
		if remaining := len(m.restore.recovered) - end; remaining > 0 {
			sb.WriteString(scrollMoreBelowLine(remaining))
			sb.WriteString("\n")
		}
	}

	if m.restore.recoveredError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(m.restore.recoveredError))
		sb.WriteString("\n")
	}

	return m.renderPopup(popupWidth, sb.String())
}

func pluralSuffixIesY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func pluralKeys(n int) string {
	if n == 1 {
		return "key"
	}
	return "keys"
}
