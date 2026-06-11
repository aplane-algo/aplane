// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "testing"

func TestRevokeTokenWarningClearsOnlyMatchingGeneration(t *testing.T) {
	m := activityReadyModel()
	m.viewState = ViewRevokeTokenConfirm

	got, cmd := updateForTest(t, m, RevokeTokenResultMsg{Success: true})
	if got.lastWarning != "Token revoked - clients must re-enroll" {
		t.Fatalf("lastWarning = %q", got.lastWarning)
	}
	if cmd == nil {
		t.Fatal("RevokeTokenResultMsg returned nil cmd, want warning clear timer")
	}
	generation := got.lastWarningGeneration

	got.setPersistentWarning("newer warning")
	got, _ = updateForTest(t, got, clearWarningMsg{Generation: generation})
	if got.lastWarning != "newer warning" {
		t.Fatalf("stale clear removed warning, got %q", got.lastWarning)
	}

	got, _ = updateForTest(t, got, clearWarningMsg{Generation: got.lastWarningGeneration})
	if got.lastWarning != "" {
		t.Fatalf("matching clear left warning = %q", got.lastWarning)
	}
}
