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

func TestTemplateLoadWarningSummaryIncludesDetail(t *testing.T) {
	tests := []struct {
		name     string
		warnings []string
		want     string
	}{
		{
			name:     "none",
			warnings: nil,
			want:     "",
		},
		{
			name:     "single",
			warnings: []string{"externally edited composed templates ignored on reload: [aplane.falcon1024-whitelist.v1]"},
			want:     "externally edited composed templates ignored on reload: [aplane.falcon1024-whitelist.v1]",
		},
		{
			name: "multiple",
			warnings: []string{
				"externally edited composed templates ignored on reload: [aplane.falcon1024-whitelist.v1]",
				"conflicting compiled key type records ignored on reload: [aplane.falcon1024_ed25519.v1]",
			},
			want: "2 template(s) failed to load: externally edited composed templates ignored on reload: [aplane.falcon1024-whitelist.v1] (+1 more)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := templateLoadWarningSummary(tt.warnings); got != tt.want {
				t.Fatalf("templateLoadWarningSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}
