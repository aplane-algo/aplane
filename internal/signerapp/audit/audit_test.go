// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

func TestRotateArchivesAndContinues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Log(AuditEntry{Event: "before-rotate"})
	if err := a.rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	a.Log(AuditEntry{Event: "after-rotate"})

	archived, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("read archived log: %v", err)
	}
	if !strings.Contains(string(archived), "before-rotate") {
		t.Fatalf("archived log missing pre-rotate entry: %s", archived)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current log: %v", err)
	}
	if !strings.Contains(string(current), "after-rotate") {
		t.Fatalf("current log missing post-rotate entry: %s", current)
	}
}

func TestCredentialRestoreDurabilityUnknownHasDistinctEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogCredentialRestoreContext(adminserver.SessionContext{}, adminproto.RestoreBackupResult{
		OperationID:     "restore-uncertain",
		GenerationID:    "gen-1-12345678",
		CommitUncertain: true,
		Error:           "CURRENT durability unconfirmed",
	})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("decode audit entry: %v\n%s", err, data)
	}
	if entry.Event != AuditCredentialRestoreUncertain || entry.Outcome != "failed" {
		t.Fatalf("audit entry = %+v", entry)
	}
}

func TestSentryReferenceAuditIncludesWitnessKeyIDAndMigrationOrigin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogSentryReferenceChangedContext(adminserver.SessionContext{}, "import", "prod-sentry", "WITNESSKEYID", "v1_client_discovery", true)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Event != AuditSentryReferenceChanged || entry.WitnessKeyID != "WITNESSKEYID" ||
		entry.Outcome != "import" || entry.MigrationOrigin != "v1_client_discovery" {
		t.Fatalf("audit entry = %+v", entry)
	}
}

func TestLogRecoversAfterLostHandle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	// Simulate the state a failed rotation leaves behind: no usable handle.
	_ = a.file.Close()
	a.file = nil

	a.Log(AuditEntry{Event: "after-failure"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "after-failure") {
		t.Fatalf("entry written after lost handle missing: %s", data)
	}
	if a.file == nil {
		t.Fatal("Log should have recovered a usable handle")
	}
}

func TestReopenCurrentRestoresByteCounter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Log(AuditEntry{Event: "sized-entry"})
	want := a.written
	if want == 0 {
		t.Fatal("expected non-zero written counter after a log entry")
	}

	_ = a.file.Close()
	a.file = nil
	a.reopenCurrent()

	if a.written != want {
		t.Fatalf("written = %d after reopen, want %d (rotation threshold drifts otherwise)", a.written, want)
	}
}
