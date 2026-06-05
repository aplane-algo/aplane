// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
	"time"
)

func TestTokenProvisioningPopupFitsPanelBody(t *testing.T) {
	m := Model{
		width:     48,
		height:    10,
		viewState: ViewTokenProvisioningPopup,
		pendingTokenRequest: &PendingTokenRequest{
			ID:             "request-1",
			IdentityID:     "default",
			SSHFingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz",
			RemoteAddr:     "127.0.0.1:12345",
			Timestamp:      time.Unix(0, 0),
		},
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
}
