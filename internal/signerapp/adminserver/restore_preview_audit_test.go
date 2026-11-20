// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type recordingPreviewAudit struct {
	recordingAuthorizationAudit
	previewed []adminproto.RestorePreviewResult
	failed    []string
}

func (a *recordingPreviewAudit) LogBackupRestorePreviewedContext(_ SessionContext, result adminproto.RestorePreviewResult) {
	a.previewed = append(a.previewed, result)
}

func (a *recordingPreviewAudit) LogBackupRestorePreviewFailedContext(_ SessionContext, reason string) {
	a.failed = append(a.failed, reason)
}

// previewAuditForTest runs a preview whose service returns result and
// reports what the session audited and wrote.
func previewAuditForTest(t *testing.T, result adminproto.RestorePreviewResult) (*recordingPreviewAudit, protocol.RestorePreviewMessage) {
	t.Helper()
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()
	svc := &stubServices{previewRestoreResult: result}
	audit := &recordingPreviewAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	conn := &queueConn{}
	session := NewSession(conn, deps, OriginLocal)
	session.Bind(auth.NewProductIdentity("test"), ir)
	session.HandlePreviewRestore(&protocol.PreviewRestoreMessage{
		BaseMessage: protocol.BaseMessage{ID: "preview-1"}, ArchivePath: "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	if len(conn.writes) != 1 {
		t.Fatalf("preview wrote %d messages, want 1", len(conn.writes))
	}
	var written protocol.RestorePreviewMessage
	if err := json.Unmarshal(conn.writes[0], &written); err != nil {
		t.Fatal(err)
	}
	return audit, written
}

// A preview that skips a key is a preview, audited with what it skips, and
// the wire carries the skipped key with its reason.
func TestPreviewWithSkippedKeysIsAuditedAsPreviewed(t *testing.T) {
	result := adminproto.RestorePreviewResult{
		ArchivePath: "backup.tar.gz",
		Keys:        []adminproto.RestoreKeyInfo{{Address: "GOOD", KeyType: "ed25519"}},
		Skipped:     []adminproto.RestoreSkipped{{Selector: "BAD", Reason: "refused"}},
	}
	audit, written := previewAuditForTest(t, result)
	if len(audit.failed) != 0 || len(audit.previewed) != 1 || !reflect.DeepEqual(audit.previewed[0], result) {
		t.Fatalf("previewed %+v, failed %q", audit.previewed, audit.failed)
	}
	want := []protocol.RestoreSkipped{{Selector: "BAD", Reason: "refused"}}
	if len(written.Keys) != 1 || !reflect.DeepEqual(written.Skipped, want) {
		t.Fatalf("written = %+v", written)
	}
}

// A preview that failed is audited as failed, with its error.
func TestFailedPreviewIsAuditedAsFailed(t *testing.T) {
	audit, _ := previewAuditForTest(t, adminproto.RestorePreviewResult{Code: protocol.ResultCodeRestorePreviewFailed, Error: "decrypt backup manifest: refused"})
	if len(audit.previewed) != 0 || len(audit.failed) != 1 || audit.failed[0] != "decrypt backup manifest: refused" {
		t.Fatalf("previewed %+v, failed %q", audit.previewed, audit.failed)
	}
}
