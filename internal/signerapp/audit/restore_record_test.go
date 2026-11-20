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

// A restore record names the operation, the archive and how many
// credentials it restored; a failed one carries the error as its reason.
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
			},
			want: map[string]any{
				"event": string(AuditCredentialRestoreSuccess), "outcome": "restored",
				"operation_id": "restore-1", "archive_sha256": "abc", "key_count": float64(2),
			},
		},
		{
			name: "failed",
			result: adminproto.RestoreBackupResult{
				OperationID: "restore-2", Code: "restore_failed", Error: "validate backup credential BAD: refused",
			},
			want: map[string]any{
				"event": string(AuditCredentialRestoreFailed), "outcome": "failed",
				"operation_id": "restore-2", "reason": "validate backup credential BAD: refused",
			},
		},
	} {
		if got := restoreRecordForTest(t, tc.result); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: record = %v, want %v", tc.name, got, tc.want)
		}
	}
}
