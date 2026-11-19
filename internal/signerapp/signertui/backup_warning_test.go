// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
)

// A backup published without a durable directory entry says so on the
// screen that reports it.
func TestBackupCreatedScreenShowsTheDurabilityWarning(t *testing.T) {
	m := updateModel(t, approvalTestModel(ViewBackupConfirm), BackupResultMsg{
		Success: true, ArchivePath: "aplane-backup-20260428-010203.tar.gz",
		Warning: "backup archive was published but directory durability could not be confirmed",
	})
	if m.viewState != ViewBackupDisplay {
		t.Fatalf("view = %v, want the backup display", m.viewState)
	}
	if view := stripANSI(m.renderBackupDisplay()); !strings.Contains(view, "durability could not be confirmed") {
		t.Fatalf("the backup display does not show the warning:\n%s", view)
	}
}
