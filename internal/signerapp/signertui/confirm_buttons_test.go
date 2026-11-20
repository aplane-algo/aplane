// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// buttonsLine is the rendered line that holds both dialog buttons, or "" when
// no line holds both.
func buttonsLine(rendered, left, right string) string {
	for _, line := range strings.Split(stripANSI(rendered), "\n") {
		if strings.Contains(line, left) && strings.Contains(line, right) {
			return line
		}
	}
	return ""
}

// The cosigner remove and the library enable/disable confirmations draw their
// buttons as every other dialog does: side by side, the focused one marked.
func TestConfirmDialogButtonsSitSideBySide(t *testing.T) {
	cosigner := Model{width: 100, height: 40, viewState: ViewCosignerRemoveConfirm,
		cosigner: cosignerState{references: testCosignerReferences(), loaded: true}}
	library := Model{width: 100, height: 40, viewState: ViewTemplateInstallConfirm, library: libraryState{
		pendingTemplate: &protocol.LibraryTemplateInfo{KeyType: "test.timed-policy.v1", TemplateType: "generic"},
	}}
	for _, focus := range []int{0, 1} {
		cosigner.cosigner.removeFocus = focus
		library.library.installFocus = focus
		for name, dialog := range map[string]struct {
			rendered, left, right string
		}{
			"cosigner remove": {cosigner.renderCosignerRemoveConfirm(), "CANCEL", "REMOVE"},
			"library enable":  {library.renderTemplateInstallConfirm(), "CANCEL", "ENABLE"},
		} {
			line := buttonsLine(dialog.rendered, dialog.left, dialog.right)
			if line == "" {
				t.Fatalf("%s, focus %d: %s and %s are not side by side:\n%s", name, focus, dialog.left, dialog.right, stripANSI(dialog.rendered))
			}
			focused, other := "> "+dialog.left, "  "+dialog.right
			if focus == 1 {
				focused, other = "> "+dialog.right, "  "+dialog.left
			}
			if !strings.Contains(line, focused) || !strings.Contains(line, other) {
				t.Fatalf("%s, focus %d: buttons %q, want %q marked and %q not", name, focus, line, focused, other)
			}
		}
	}
}
