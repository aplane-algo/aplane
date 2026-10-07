// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "testing"

func TestEnrollmentWithdrawnWarningClearsOnlyMatchingGeneration(t *testing.T) {
	m := activityReadyModel()
	m.enrollmentApproval.request = &PendingEnrollmentRequest{ID: "enroll-1"}

	got, cmd := updateForTest(t, m, ClientEnrollmentCanceledMsg{ID: "enroll-1"})
	if got.lastWarning != tokenProvisioningCanceledWarning("") {
		t.Fatalf("lastWarning = %q", got.lastWarning)
	}
	if cmd == nil {
		t.Fatal("ClientEnrollmentCanceledMsg returned nil cmd, want warning clear timer")
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

func TestLocalIdleWarningClearsAfterSuccessfulAuth(t *testing.T) {
	m := activityReadyModel()
	m.viewState = ViewAuth
	m.setPersistentWarning(localIdleDisconnectReason)

	got, _ := updateForTest(t, m, AuthResultMsg{Success: true})

	if got.lastWarning != "" {
		t.Fatalf("lastWarning = %q, want cleared", got.lastWarning)
	}
}

func TestLocalIdleWarningClearsAfterSuccessfulUnlock(t *testing.T) {
	m := activityReadyModel()
	m.viewState = ViewUnlock
	m.setPersistentWarning(localIdleDisconnectReason)

	got, _ := updateForTest(t, m, UnlockResultMsg{Success: true})

	if got.lastWarning != "" {
		t.Fatalf("lastWarning = %q, want cleared", got.lastWarning)
	}
}

func TestValidAdminSettingsClearInvalidTimeoutWarning(t *testing.T) {
	m := activityReadyModel()
	m.setPersistentWarning(invalidPassphraseTimeoutWarningPrefix + "bad timeout")

	_ = m.applyAdminSettingsTimeout(AdminSettings{PassphraseTimeout: "5m"})

	if m.lastWarning != "" {
		t.Fatalf("lastWarning = %q, want cleared", m.lastWarning)
	}
}

func TestValidAdminSettingsKeepUnrelatedWarning(t *testing.T) {
	m := activityReadyModel()
	m.setPersistentWarning("unrelated warning")

	_ = m.applyAdminSettingsTimeout(AdminSettings{PassphraseTimeout: "5m"})

	if m.lastWarning != "unrelated warning" {
		t.Fatalf("lastWarning = %q, want unrelated warning preserved", m.lastWarning)
	}
}
