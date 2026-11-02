// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "testing"

// The reason a session ended belongs to the disconnected screen only; a new
// connection clears it.
func TestConnectedClearsSessionEndedReason(t *testing.T) {
	m := activityReadyModel()
	m.viewState = ViewAuth
	m.connectionState = ConnectionConnecting
	m.auth.endedReason = localIdleDisconnectReason

	got, _ := updateForTest(t, m, ConnectedMsg{})

	if got.auth.endedReason != "" {
		t.Fatalf("endedReason = %q, want cleared", got.auth.endedReason)
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
