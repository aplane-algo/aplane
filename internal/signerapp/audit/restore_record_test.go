// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// restoreRecordForTest logs result as a credential restore outcome and
// returns the entry's JSON object without its timestamp and transport.
func restoreRecordForTest(t *testing.T, result adminproto.RestoreBackupResult) map[string]any {
	t.Helper()
	return recordForTest(t, func(a *AuditLogger) { a.LogCredentialRestoreContext(adminserver.SessionContext{}, result) })
}

// A restore record names the operation, the archive, how many credentials it
// restored, listed or not, and the ones it skipped; a failed one carries the error as its
// reason, and still names what it skipped.
func TestCredentialRestoreRecordShape(t *testing.T) {
	restored := []adminproto.RestoreCredential{{Selector: "ADDR1"}, {Selector: "ADDR2"}}
	for _, tc := range []struct {
		name   string
		result adminproto.RestoreBackupResult
		want   map[string]any
	}{
		{
			name: "succeeded",
			result: adminproto.RestoreBackupResult{
				Success: true, OperationID: "restore-1", ArchiveSHA256: "abc", GenerationID: "gen-2",
				Restored: restored, RestoredOmitted: 3, Identical: []adminproto.RestoreCredential{{Selector: "ADDR3"}}, PoliciesRestored: []string{"ADDR1"},
				Skipped:        []adminproto.RestoreSkipped{{Selector: "BAD1", Reason: "refused"}, {Selector: "BAD2", Reason: "refused"}},
				SkippedOmitted: 5,
			},
			want: map[string]any{
				"event": string(AuditCredentialRestoreSuccess), "outcome": "restored",
				"operation_id": "restore-1", "archive_sha256": "abc", "key_count": float64(5),
				"skipped_keys": []any{"BAD1", "BAD2"}, "skipped_keys_omitted": float64(5),
			},
		},
		{
			name: "failed",
			result: adminproto.RestoreBackupResult{
				OperationID: "restore-2", Code: "restore_failed", Error: "selected credential cannot be restored: BAD: refused",
				Skipped: []adminproto.RestoreSkipped{{Selector: "BAD", Reason: "refused"}},
			},
			want: map[string]any{
				"event": string(AuditCredentialRestoreFailed), "outcome": "failed",
				"operation_id": "restore-2", "reason": "selected credential cannot be restored: BAD: refused",
				"skipped_keys": []any{"BAD"},
			},
		},
	} {
		if got := restoreRecordForTest(t, tc.result); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: record = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A preview record names the archive, how many credentials a restore would
// admit, and the ones it would skip.
func TestRestorePreviewRecordShape(t *testing.T) {
	record := recordForTest(t, func(a *AuditLogger) {
		a.LogBackupRestorePreviewedContext(adminserver.SessionContext{}, adminproto.RestorePreviewResult{
			ArchivePath: "backup.tar.gz",
			Keys:        []adminproto.RestoreKeyInfo{{Address: "GOOD"}},
			Skipped:     []adminproto.RestoreSkipped{{Selector: "BAD", Reason: "refused"}},
		})
	})
	want := map[string]any{
		"event": string(AuditBackupRestorePreviewed), "outcome": "previewed", "archive": "backup.tar.gz",
		"key_count": float64(1), "skipped_keys": []any{"BAD"},
	}
	if !reflect.DeepEqual(record, want) {
		t.Fatalf("record = %v, want %v", record, want)
	}
}

// An import record names the archive and the keys in it a restore would
// skip, selectors only and at most 64 of them, as the restore records do.
func TestBackupImportedRecordShape(t *testing.T) {
	skipped := make([]adminproto.RestoreSkipped, 70)
	selectors := make([]any, 0, maxAuditSelectors)
	for i := range skipped {
		skipped[i] = adminproto.RestoreSkipped{Selector: fmt.Sprintf("KEY%02d", i), Reason: "refused"}
		if i < maxAuditSelectors {
			selectors = append(selectors, skipped[i].Selector)
		}
	}
	for _, tc := range []struct {
		name   string
		result adminproto.CommitBackupImportResult
		want   map[string]any
	}{
		{
			name:   "no skips",
			result: adminproto.CommitBackupImportResult{Success: true, Backup: adminproto.BackupInfo{FileName: "import.tar.gz", Size: 42}},
			want:   map[string]any{"event": string(AuditBackupImported), "outcome": "imported", "archive": "import.tar.gz", "byte_count": float64(42)},
		},
		{
			name: "a list the result already bounded",
			result: adminproto.CommitBackupImportResult{
				Success: true, Backup: adminproto.BackupInfo{FileName: "import.tar.gz", Size: 42},
				Skipped: skipped[:maxAuditSelectors], SkippedOmitted: 6,
			},
			want: map[string]any{
				"event": string(AuditBackupImported), "outcome": "imported", "archive": "import.tar.gz", "byte_count": float64(42),
				"skipped_keys": selectors, "skipped_keys_omitted": float64(6),
			},
		},
		{
			name: "skips",
			result: adminproto.CommitBackupImportResult{
				Success: true, Backup: adminproto.BackupInfo{FileName: "import.tar.gz", Size: 42}, Skipped: skipped,
			},
			want: map[string]any{
				"event": string(AuditBackupImported), "outcome": "imported", "archive": "import.tar.gz", "byte_count": float64(42),
				"skipped_keys": selectors, "skipped_keys_omitted": float64(6),
			},
		},
	} {
		got := recordForTest(t, func(a *AuditLogger) { a.LogBackupImportedContext(adminserver.SessionContext{}, tc.result) })
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: record = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// recordForTest runs log against a fresh audit log and returns the one
// entry it wrote, without its timestamp and transport.
func recordForTest(t *testing.T, log func(*AuditLogger)) map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	log(a)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decode audit entry: %v\n%s", err, data)
	}
	delete(record, "timestamp")
	delete(record, "transport")
	return record
}

// Each event writes its facts to fields of their own, and its reason keeps
// only the cause, if any.
func TestTypedFieldRecordShapes(t *testing.T) {
	longPath := "/backups/" + strings.Repeat("p", 300) + ".tar.gz"
	for _, tc := range []struct {
		name string
		log  func(*AuditLogger)
		want map[string]any
	}{
		{
			name: "backup created",
			log:  func(a *AuditLogger) { a.LogBackupCreatedContext(adminserver.SessionContext{}, "/backups/b.tar.gz") },
			want: map[string]any{"event": string(AuditBackupCreated), "outcome": "created", "archive": "/backups/b.tar.gz"},
		},
		{
			name: "backup export started",
			log:  func(a *AuditLogger) { a.LogBackupExportStartedContext(adminserver.SessionContext{}, "b.tar.gz") },
			want: map[string]any{"event": string(AuditBackupExportStarted), "outcome": "started", "archive": "b.tar.gz"},
		},
		{
			// A path past maxAuditField is kept whole.
			name: "backup delete failed",
			log: func(a *AuditLogger) {
				a.LogBackupDeletedContext(adminserver.SessionContext{}, longPath, adminproto.DeleteBackupResult{
					Code: "delete_backup_failed", Error: "not found",
				})
			},
			want: map[string]any{
				"event": string(AuditBackupDeleted), "outcome": "failed", "archive": longPath,
				"result_code": "delete_backup_failed", "reason": "not found",
			},
		},
		{
			name: "rotating recovery with a grant",
			log: func(a *AuditLogger) {
				a.LogRotatingRecoveryAttributed(Attribution{}, "ACCT", "cancel", 7, "cancelled")
			},
			want: map[string]any{
				"event": string(AuditRotatingRecovery), "outcome": "cancel", "txn_auth": "ACCT",
				"grant_id": float64(7), "reason": "cancelled",
			},
		},
		{
			name: "rotating recovery without one",
			log: func(a *AuditLogger) {
				a.LogRotatingRecoveryAttributed(Attribution{}, "ACCT", "cancel", 0, "nothing to cancel")
			},
			want: map[string]any{
				"event": string(AuditRotatingRecovery), "outcome": "cancel", "txn_auth": "ACCT",
				"reason": "nothing to cancel",
			},
		},
		{
			name: "authorization denied",
			log: func(a *AuditLogger) {
				a.LogAuthorizationDenied(adminserver.SessionContext{}, "keys.delete", auth.Resource{Type: "key", ID: "ADDR"}, "forbidden")
			},
			want: map[string]any{
				"event": string(AuditAuthorizationDenied), "outcome": "denied",
				"authorization_action": "keys.delete", "resource_type": "key", "resource_id": "ADDR", "reason": "forbidden",
			},
		},
		{
			name: "key generated",
			log:  func(a *AuditLogger) { a.LogKeyGenerated(context.Background(), "ADDR", "ed25519") },
			want: map[string]any{"event": string(AuditKeyGenerated), "outcome": "generated", "txn_auth": "ADDR", "key_type": "ed25519"},
		},
		{
			name: "key imported",
			log:  func(a *AuditLogger) { a.LogKeyImported(context.Background(), "ADDR", "falcon1024") },
			want: map[string]any{"event": string(AuditKeyImported), "outcome": "imported", "txn_auth": "ADDR", "key_type": "falcon1024"},
		},
		{
			name: "key deleted",
			log:  func(a *AuditLogger) { a.LogKeyDeleted(context.Background(), "ADDR", "/keys/deleted/ADDR.key") },
			want: map[string]any{"event": string(AuditKeyDeleted), "outcome": "deleted", "txn_auth": "ADDR", "key_file": "ADDR.key"},
		},
		{
			// A path that names no file leaves key_file out.
			name: "key deleted at a path with no name",
			log:  func(a *AuditLogger) { a.LogKeyDeleted(context.Background(), "ADDR", "/") },
			want: map[string]any{"event": string(AuditKeyDeleted), "outcome": "deleted", "txn_auth": "ADDR"},
		},
		{
			name: "client enrollment requested",
			log:  func(a *AuditLogger) { a.LogClientEnrollmentRequested("SHA256:abc", "laptop", "10.0.0.1:5") },
			want: map[string]any{
				"event": string(AuditClientEnrollmentRequested), "outcome": "pending", "ssh_fingerprint": "SHA256:abc",
				"client_label": "laptop", "remote_addr": "10.0.0.1:5",
			},
		},
		{
			name: "client enrolled",
			log: func(a *AuditLogger) {
				a.LogClientEnrolledContext(adminserver.SessionContext{}, "SHA256:abc", "laptop", "10.0.0.1:5")
			},
			want: map[string]any{
				"event": string(AuditClientEnrolled), "outcome": "enrolled", "ssh_fingerprint": "SHA256:abc",
				"client_label": "laptop", "remote_addr": "10.0.0.1:5",
			},
		},
		{
			name: "client enrollment rejected",
			log: func(a *AuditLogger) {
				a.LogClientEnrollmentRejectedContext(adminserver.SessionContext{}, "SHA256:abc", "laptop")
			},
			want: map[string]any{
				"event": string(AuditClientEnrollmentRejected), "outcome": "rejected", "ssh_fingerprint": "SHA256:abc",
				"client_label": "laptop",
			},
		},
		{
			name: "client key revoked",
			log: func(a *AuditLogger) {
				a.LogClientKeyRevokedContext(adminserver.SessionContext{}, "SHA256:abc", "laptop", 2)
			},
			want: map[string]any{
				"event": string(AuditClientKeyRevoked), "outcome": "revoked", "ssh_fingerprint": "SHA256:abc",
				"client_label": "laptop", "closed_connections": float64(2),
			},
		},
		{
			name: "authorization denied without a resource ID or cause",
			log: func(a *AuditLogger) {
				a.LogAuthorizationDenied(adminserver.SessionContext{}, "keys.list", auth.Resource{Type: "key"}, "")
			},
			want: map[string]any{
				"event": string(AuditAuthorizationDenied), "outcome": "denied",
				"authorization_action": "keys.list", "resource_type": "key",
			},
		},
	} {
		got := recordForTest(t, tc.log)
		for _, principal := range []string{"principal", "requester_principal"} {
			delete(got, principal)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: record = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A key file's name is recorded only when there is one: a path with no name
// leaves the field out.
func TestKeyRejectedNamesOnlyARealFile(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/keys/BAD.key", "BAD.key"},
		{"", ""},
		{"/", ""},
		{".", ""},
	} {
		record := recordForTest(t, func(a *AuditLogger) { a.LogKeyRejected(tc.path, "invalid") })
		if got, _ := record["key_file"].(string); got != tc.want || record["reason"] != "invalid" {
			t.Errorf("%q: record = %v, want key_file %q and reason invalid", tc.path, record, tc.want)
		}
	}
}

// A name or path is kept whole up to maxAuditName, 4096 bytes, and cut past
// it, in each field that holds one.
func TestNamesAndPathsAreKeptWholeTo4096Bytes(t *testing.T) {
	for _, n := range []int{4096, 4097} {
		name := strings.Repeat("n", n)
		for _, tc := range []struct {
			field string
			log   func(*AuditLogger)
		}{
			{"archive", func(a *AuditLogger) { a.LogBackupCreatedContext(adminserver.SessionContext{}, name) }},
			{"key_file", func(a *AuditLogger) { a.LogKeyRejected(name, "invalid") }},
			{"resource_id", func(a *AuditLogger) {
				a.LogAuthorizationDenied(adminserver.SessionContext{}, "backups.export", auth.Resource{Type: "backup", ID: name}, "")
			}},
			{"cosigner_name", func(a *AuditLogger) {
				a.LogCosignerReferenceChangedContext(adminserver.SessionContext{}, "import", name, "W", true)
			}},
		} {
			got, _ := recordForTest(t, tc.log)[tc.field].(string)
			if whole := got == name; whole != (n <= 4096) || len(got) > 4096 {
				t.Errorf("%s of %d bytes: logged %d bytes, whole %v", tc.field, n, len(got), whole)
			}
		}
	}
}
