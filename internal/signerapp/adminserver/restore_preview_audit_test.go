// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type recordingPreviewAudit struct {
	recordingAuthorizationAudit
	previewed []string
	failed    []string
}

func (a *recordingPreviewAudit) LogBackupRestorePreviewedContext(_ SessionContext, archivePath string, keyCount int) {
	a.previewed = append(a.previewed, archivePath)
	_ = keyCount
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

// A preview whose keys report errors is audited as a failed preview.
func TestPreviewWithKeyErrorsIsAuditedAsFailed(t *testing.T) {
	audit, written := previewAuditForTest(t, adminproto.RestorePreviewResult{
		ArchivePath: "backup.tar.gz",
		Keys:        []adminproto.RestoreKeyInfo{{Address: "GOOD", KeyType: "ed25519"}, {Address: "BAD", Error: "refused"}},
		Errors:      []adminproto.RestoreError{{Address: "BAD", Error: "refused"}},
	})
	if len(audit.previewed) != 0 || len(audit.failed) != 1 || audit.failed[0] != "restore preview returned key errors" {
		t.Fatalf("previewed %q, failed %q", audit.previewed, audit.failed)
	}
	if len(written.Keys) != 2 || written.Keys[1].Error != "refused" || len(written.Errors) != 1 {
		t.Fatalf("written = %+v", written)
	}
}
