// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// A daemon whose audit log could not be opened has a nil logger. Every durable
// intent is refused, so the change it precedes does not run, and every other
// record is dropped.
func TestANilLoggerRefusesIntentsAndRecordsNothing(t *testing.T) {
	var logger *AuditLogger
	value := reflect.ValueOf(logger)
	intents := 0
	for i := range value.NumMethod() {
		name := value.Type().Method(i).Name
		if !strings.HasPrefix(name, "Log") {
			continue
		}
		method := value.Method(i)
		args := make([]reflect.Value, method.Type().NumIn())
		for j := range args {
			args[j] = reflect.Zero(method.Type().In(j))
		}
		out := method.Call(args)
		if len(out) == 0 {
			continue
		}
		intents++
		if err, _ := out[0].Interface().(error); !errors.Is(err, adminserver.ErrAuditUnavailable) {
			t.Errorf("%s on a nil logger = %v, want ErrAuditUnavailable", name, err)
		}
	}
	if intents == 0 {
		t.Fatal("no durable intent was called")
	}
}

func adminRecords(t *testing.T, record func(*AuditLogger, adminserver.SessionContext)) []AuditEntry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	record(logger, adminserver.SessionContext{
		SessionID:      "s-1",
		Origin:         adminserver.OriginLocal,
		AdminPrincipal: adminserver.SessionPrincipal{ID: "admin-principal"},
	})
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntries(t, path)
	for _, entry := range entries {
		if entry.Principal != "admin-principal" || entry.AdminSessionID != "s-1" || entry.Transport != "ipc" {
			t.Errorf("%s is attributed to %q in session %q over %q", entry.Event, entry.Principal, entry.AdminSessionID, entry.Transport)
		}
	}
	return entries
}

func TestBackupDeletionsAndReconcilesAreRecorded(t *testing.T) {
	entries := adminRecords(t, func(a *AuditLogger, ctx adminserver.SessionContext) {
		a.LogBackupDeletedContext(ctx, "b.tar.gz", adminproto.DeleteBackupResult{Success: true})
		a.LogBackupDeletedContext(ctx, "b.tar.gz", adminproto.DeleteBackupResult{Code: "delete_backup_failed", Error: "not found"})
		a.LogStoreReconciledContext(ctx, adminproto.ReconcileStoreResult{Success: true, GenerationID: "gen-2", KeyCount: 3})
		a.LogStoreReconciledContext(ctx, adminproto.ReconcileStoreResult{Code: "recovery_blocked", Error: "damaged"})
	})
	type record struct {
		event                                  AuditEventType
		outcome, code, archive, reason, genera string
		keys                                   int
	}
	var got []record
	for _, e := range entries {
		got = append(got, record{e.Event, e.Outcome, e.ResultCode, e.Archive, e.Reason, e.GenerationID, e.KeyCount})
	}
	want := []record{
		{AuditBackupDeleted, "deleted", "", "b.tar.gz", "", "", 0},
		{AuditBackupDeleted, "failed", "delete_backup_failed", "b.tar.gz", "not found", "", 0},
		{AuditStoreReconciled, "succeeded", "", "", "", "gen-2", 3},
		{AuditStoreReconciled, "failed", "recovery_blocked", "", "damaged", "", 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
}

// A key type change names the action, the key type and whether the store
// changed, false included. A failure that does not say leaves that out.
func TestKeyTypeChangesAreRecorded(t *testing.T) {
	yes, no := true, false
	entries := adminRecords(t, func(a *AuditLogger, ctx adminserver.SessionContext) {
		a.LogKeyTypeChangedContext(ctx, adminserver.KeyTypeChange{Action: "install", KeyType: "lab.escrow.v1", Success: true, Changed: &yes})
		a.LogKeyTypeChangedContext(ctx, adminserver.KeyTypeChange{Action: "activate", KeyType: "lab.escrow.v1", Success: true, Changed: &no})
		a.LogKeyTypeChangedContext(ctx, adminserver.KeyTypeChange{Action: "remove", KeyType: "lab.escrow.v1", Changed: &yes, Code: "reload_failed", Error: "damaged"})
		a.LogKeyTypeChangedContext(ctx, adminserver.KeyTypeChange{Action: "import", Code: "import_failed", Error: "not YAML"})
	})
	type record struct {
		action, keyType, outcome, code, reason, changed string
	}
	var got []record
	for _, e := range entries {
		changed := "unsaid"
		if e.Changed != nil {
			changed = map[bool]string{true: "yes", false: "no"}[*e.Changed]
		}
		if e.Event != AuditKeyTypeChanged {
			t.Fatalf("event = %s", e.Event)
		}
		got = append(got, record{e.KeyTypeAction, e.KeyType, e.Outcome, e.ResultCode, e.Reason, changed})
	}
	want := []record{
		{"install", "lab.escrow.v1", "succeeded", "", "", "yes"},
		{"activate", "lab.escrow.v1", "succeeded", "", "", "no"},
		{"remove", "lab.escrow.v1", "failed", "reload_failed", "damaged", "yes"},
		{"import", "", "failed", "import_failed", "not YAML", "unsaid"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
}

// A flood of client authentication failures, which anyone who reaches the SSH
// port can cause, leaves an admin login failure recorded. A flood of those is
// summarized too, in an entry of its own.
func TestAdminLoginFailuresHaveTheirOwnLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	logger.authFailures.now = func() time.Time { return now }
	logger.adminLoginFailures.now = func() time.Time { return now }
	const flood = 1000
	for range flood {
		logger.LogAuthFailed("127.0.0.1:1", "invalid_credentials")
	}
	ctx := adminserver.SessionContext{SessionID: "s-1", Origin: adminserver.OriginLocal}
	logger.LogAdminLoginFailedContext(ctx, "wrong passphrase")
	entries := readAuditEntries(t, path)
	last := entries[len(entries)-1]
	if last.Event != AuditAdminLoginFailed || last.Outcome != "failed" || last.Reason != "wrong passphrase" ||
		last.AdminSessionID != "s-1" || last.Transport != "ipc" || last.Principal != "" {
		t.Fatalf("last entry = %+v, want the admin login failure, with no principal", last)
	}

	for range flood {
		logger.LogAdminLoginFailedContext(ctx, "wrong passphrase")
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	entries = readAuditEntries(t, path)
	if got := countEvents(entries, AuditAdminLoginFailed); got != authFailureBurst {
		t.Fatalf("individual admin login failures = %d, want the burst of %d", got, authFailureBurst)
	}
	if got := countEvents(entries, AuditAdminLoginFailuresSuppressed); got != 1 {
		t.Fatalf("admin login summaries = %d, want 1", got)
	}
}
