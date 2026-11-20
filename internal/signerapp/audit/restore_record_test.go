// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// restoreRecordForTest logs result as a credential restore outcome and
// returns the entry's JSON object without its timestamp and transport.
func restoreRecordForTest(t *testing.T, result adminproto.RestoreBackupResult) map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogCredentialRestoreContext(adminserver.SessionContext{}, result)
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

// A restore record names the operation, the archive, how many credentials it
// restored and the ones it skipped; a failed one carries the error as its
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
				Restored: restored, Identical: []adminproto.RestoreCredential{{Selector: "ADDR3"}}, PoliciesRestored: []string{"ADDR1"},
				Skipped: []adminproto.RestoreSkipped{{Selector: "BAD1", Reason: "refused"}, {Selector: "BAD2", Reason: "refused"}},
			},
			want: map[string]any{
				"event": string(AuditCredentialRestoreSuccess), "outcome": "restored",
				"operation_id": "restore-1", "archive_sha256": "abc", "key_count": float64(2),
				"skipped_keys": []any{"BAD1", "BAD2"},
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
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogBackupRestorePreviewedContext(adminserver.SessionContext{}, adminproto.RestorePreviewResult{
		ArchivePath: "backup.tar.gz",
		Keys:        []adminproto.RestoreKeyInfo{{Address: "GOOD"}},
		Skipped:     []adminproto.RestoreSkipped{{Selector: "BAD", Reason: "refused"}},
	})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	delete(record, "timestamp")
	delete(record, "transport")
	want := map[string]any{
		"event": string(AuditBackupRestorePreviewed), "outcome": "previewed", "reason": "backup.tar.gz",
		"key_count": float64(1), "skipped_keys": []any{"BAD"},
	}
	if !reflect.DeepEqual(record, want) {
		t.Fatalf("record = %v, want %v", record, want)
	}
}
