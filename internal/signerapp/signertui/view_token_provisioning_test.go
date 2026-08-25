// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
)

func TestTokenProvisioningPopupFitsPanelBody(t *testing.T) {
	m := Model{
		width:     48,
		height:    10,
		viewState: ViewTokenProvisioningPopup,
		tokenApproval: tokenApprovalState{request: &PendingTokenRequest{
			ID:             "request-1",
			SSHFingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz",
			RemoteAddr:     "127.0.0.1:12345",
		}},
	}

	rendered := m.renderTokenProvisioningPopup()
	if lines, maxLines := visibleLineCount(rendered), m.windowBodyHeight(); lines > maxLines {
		t.Fatalf("token provisioning popup line count = %d, want <= body height %d\n%s",
			lines, maxLines, stripANSI(rendered))
	}
	clean := stripANSI(rendered)
	if !strings.Contains(clean, "╚") && !strings.Contains(clean, "╰") {
		t.Fatalf("token provisioning popup missing bottom border:\n%s", clean)
	}
	for _, unwanted := range []string{"Identity:", "Timestamp:", "This will issue"} {
		if strings.Contains(clean, unwanted) {
			t.Fatalf("token provisioning popup contains %q:\n%s", unwanted, clean)
		}
	}
}
