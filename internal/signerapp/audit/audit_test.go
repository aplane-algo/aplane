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

func TestRecoveredActivationAuditCarriesSecurityContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
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
	result := adminproto.ActivateRecoveredResult{
		Success:                 true,
		RestoreID:               "0123456789abcdef0123456789abcdef",
		Activated:               []adminproto.RecoveredReviewEntry{{Selector: "ADDR1"}},
		ArchiveSHA256:           "archive-digest",
		SourcePolicySHA256:      "source-policy-digest",
		DestinationPolicySHA256: "destination-policy-digest",
		PolicyComparison:        "different",
		ReplaceExisting:         true,
	}
	a.LogBackupActivationIntentContext(ctx, result.RestoreID, result.ReplaceExisting)
	a.LogBackupActivatedContext(ctx, result)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit entry count = %d, want 2", len(lines))
	}
	var activated AuditEntry
	if err := json.Unmarshal([]byte(lines[1]), &activated); err != nil {
		t.Fatal(err)
	}
	if activated.Event != AuditBackupActivated ||
		activated.RestoreID != result.RestoreID ||
		activated.ArchiveSHA256 != result.ArchiveSHA256 ||
		activated.SourcePolicySHA256 != result.SourcePolicySHA256 ||
		activated.DestinationPolicySHA256 != result.DestinationPolicySHA256 ||
		activated.PolicyComparison != result.PolicyComparison ||
		!activated.ReplaceExisting ||
		activated.KeyCount != 1 {
		t.Fatalf("activated audit entry = %#v", activated)
	}
}
