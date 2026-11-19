// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// A list that could not be read is not an empty one: the screen says the
// list failed, and a list that arrives later replaces the error.

func TestFailedBackupListShowsTheErrorNotAnEmptyRepository(t *testing.T) {
	m := backupsModel()
	m.restore.backupsLoaded = false
	m, _ = update(t, m, BackupsListMsg{Error: "open backups: permission denied"})
	view := stripANSI(m.renderBackups())
	if !strings.Contains(view, "Backup list failed: open backups: permission denied") ||
		strings.Contains(view, "No backups yet") || strings.Contains(view, "0 backups") {
		t.Fatalf("a failed first list:\n%s", view)
	}

	listed := BackupInfo{FileName: "lab-signer.tar.gz", Path: "lab-signer.tar.gz", Size: 100}
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{listed}})
	m, _ = update(t, m, BackupsListMsg{Error: "read backups: input/output error"})
	view = stripANSI(m.renderBackups())
	if !strings.Contains(view, "Backup list failed: read backups: input/output error") ||
		!strings.Contains(view, "Showing the last list read.") || !strings.Contains(view, "lab-signer.tar.gz") ||
		strings.Contains(view, "1 backup on this signer") {
		t.Fatalf("a failed refresh:\n%s", view)
	}

	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{listed}})
	if view = stripANSI(m.renderBackups()); strings.Contains(view, "Backup list failed") || !strings.Contains(view, "1 backup on this signer") {
		t.Fatalf("a list after the failure:\n%s", view)
	}
}

func TestFailedCosignerListShowsTheErrorNotAnEmptyList(t *testing.T) {
	m := Model{viewState: ViewCosignerReferences, width: 100, height: 40}
	m, _ = update(t, m, CosignerReferencesMsg{Error: "list cosigner references: permission denied"})
	view := stripANSI(m.renderCosignerReferences())
	if !strings.Contains(view, "Cosigner references could not be listed: list cosigner references: permission denied") ||
		strings.Contains(view, "No cosigner references enrolled") {
		t.Fatalf("a failed list:\n%s", view)
	}
	// Nor does the Generate form's picker, which for an empty list goes
	// straight to a new import.
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{KeyType: secondPerKeyType, CosignerComponentKeyTypes: []string{"aplane.falcon1024.v1"}}})
	if _, errMsg := m.openCosignerPicker(secondPerKeyType, "cosigner"); !strings.Contains(errMsg, "could not be listed: list cosigner references: permission denied") {
		t.Fatalf("picker after a failed list: %q", errMsg)
	}

	m, _ = update(t, m, CosignerReferencesMsg{References: testCosignerReferences()})
	m, _ = update(t, m, CosignerReferencesMsg{Error: "list cosigner references: input/output error"})
	view = stripANSI(m.renderCosignerReferences())
	if !strings.Contains(view, "could not be listed: list cosigner references: input/output error") ||
		!strings.Contains(view, "Showing the last list read.") || !strings.Contains(view, "west") {
		t.Fatalf("a failed refresh:\n%s", view)
	}

	m, _ = update(t, m, CosignerReferencesMsg{References: testCosignerReferences()})
	if view = stripANSI(m.renderCosignerReferences()); strings.Contains(view, "could not be listed") {
		t.Fatalf("a list after the failure:\n%s", view)
	}
	if next, errMsg := m.openCosignerPicker(secondPerKeyType, "cosigner"); errMsg != "" || next.viewState != ViewCosignerPicker {
		t.Fatalf("picker after a list: view %v, error %q", next.viewState, errMsg)
	}
}
