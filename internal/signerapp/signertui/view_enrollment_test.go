// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
)

func TestClientEnrollmentPopupFitsPanelBody(t *testing.T) {
	m := Model{
		width:     48,
		height:    10,
		viewState: ViewClientEnrollmentPopup,
		enrollmentApproval: enrollmentApprovalState{request: &PendingEnrollmentRequest{
			ID:             "request-1",
			SSHFingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz",
			RemoteAddr:     "127.0.0.1:12345",
		}},
	}

	rendered := m.renderClientEnrollmentPopup()
	if lines, maxLines := visibleLineCount(rendered), m.windowBodyHeight(); lines > maxLines {
		t.Fatalf("client enrollment popup line count = %d, want <= body height %d\n%s",
			lines, maxLines, stripANSI(rendered))
	}
	clean := stripANSI(rendered)
	if !strings.Contains(clean, "╚") && !strings.Contains(clean, "╰") {
		t.Fatalf("client enrollment popup missing bottom border:\n%s", clean)
	}
	for _, unwanted := range []string{"Identity:", "Timestamp:", "This will issue"} {
		if strings.Contains(clean, unwanted) {
			t.Fatalf("client enrollment popup contains %q:\n%s", unwanted, clean)
		}
	}
}

func TestEnrollmentRequestDisplaysFullClientFingerprintAndLabel(t *testing.T) {
	fingerprint := "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	m := Model{width: 110, height: 24, viewState: ViewClientEnrollmentPopup, enrollmentApproval: enrollmentApprovalState{request: &PendingEnrollmentRequest{SSHFingerprint: fingerprint, Label: "laptop", RemoteAddr: "[2001:db8::1234]:54321"}}}
	rendered := stripANSI(m.renderClientEnrollmentPopup())
	if !strings.Contains(rendered, fingerprint) {
		t.Fatalf("fingerprint lost: %s", rendered)
	}
	if !strings.Contains(rendered, "Requested label: laptop") || !strings.Contains(rendered, "No credential is issued") {
		t.Fatalf("label or no-credential notice missing: %s", rendered)
	}
}
