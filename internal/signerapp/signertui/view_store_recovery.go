// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "strings"

func (m Model) renderStoreRecovery() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Store Recovery"))
	sb.WriteString("\n")
	if m.signerState == signerRuntimeRecovery {
		sb.WriteString(errorStyle.Render("Signing is disabled because the active store has not validated cleanly."))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString(subtitleStyle.Render("The active store is currently available."))
		sb.WriteString("\n\n")
	}
	sb.WriteString("r  Reconcile and validate the current generation\n")
	sb.WriteString("x  Roll back the latest clean credential restore\n")
	sb.WriteString("b  Restore credentials from a backup archive\n")
	sb.WriteString("l  Lock the signer\n")
	sb.WriteString("q  Quit\n")
	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("A restore may repair a damaged credential only when replacement is explicitly confirmed."))
	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("If reconciliation and authenticated rollback both fail, preserve evidence and use offline apstore rebuild."))
	sb.WriteString("\n")
	if m.restore.recoveryError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(m.restore.recoveryError))
		sb.WriteString("\n")
	}
	return m.renderPopup(m.popupWidth(96), sb.String())
}

func pluralKeys(n int) string {
	if n == 1 {
		return "key"
	}
	return "keys"
}
