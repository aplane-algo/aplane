// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

func TestLogBackupActivationIntentDurableWritesEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	ctx := adminserver.SessionContext{
		TargetIdentityID: "alice",
		SessionID:        "admin-session",
		Transport:        "ipc",
	}
	if err := a.LogBackupActivationIntentDurableContext(ctx, "0123456789abcdef0123456789abcdef", true); err != nil {
		t.Fatalf("LogBackupActivationIntentDurableContext: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var entry AuditEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if entry.Event != AuditBackupActivationIntent {
		t.Fatalf("event = %q, want %q", entry.Event, AuditBackupActivationIntent)
	}
	if entry.Outcome != "requested" {
		t.Fatalf("outcome = %q, want requested", entry.Outcome)
	}
	if entry.RestoreID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("restore_id = %q", entry.RestoreID)
	}
	if !entry.ReplaceExisting {
		t.Fatal("replace_existing not recorded")
	}
}

func TestLogBackupActivationIntentDurableFailsOnWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	// A closed handle makes the write fail while a.file stays non-nil, the
	// state a torn rotation can leave behind.
	_ = a.file.Close()

	if err := a.LogBackupActivationIntentDurableContext(adminserver.SessionContext{}, "0123456789abcdef0123456789abcdef", false); err == nil {
		t.Fatal("expected error when the audit write fails")
	}
}

func TestLogBackupActivationIntentDurableFailsWhenLogUnavailable(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "gone")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(nested, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	// No usable handle and no way to reopen: the log's directory is gone.
	_ = a.file.Close()
	a.file = nil
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove log: %v", err)
	}
	if err := os.Remove(nested); err != nil {
		t.Fatalf("remove log dir: %v", err)
	}

	if err := a.LogBackupActivationIntentDurableContext(adminserver.SessionContext{}, "0123456789abcdef0123456789abcdef", false); err == nil {
		t.Fatal("expected error when the audit log is unavailable")
	}
}

func TestOrdinaryLogStaysBestEffortOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	// Log has no error to surface; a failed write must stay a warning, not a
	// panic, and must not poison later entries once the handle recovers.
	_ = a.file.Close()
	a.file = nil

	a.Log(AuditEntry{Event: "best-effort"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "best-effort") {
		t.Fatalf("Log did not recover and write the entry: %s", data)
	}
}
