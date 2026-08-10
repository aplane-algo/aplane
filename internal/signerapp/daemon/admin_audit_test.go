// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

func TestAdminSessionAuditSatisfiesHandlerProbes(t *testing.T) {
	audit := (&Signer{}).adminSessionDeps().Audit
	if _, ok := audit.(interface {
		LogIdentityLockedContext(adminserver.SessionContext, string)
		LogBackupCreatedContext(adminserver.SessionContext, string)
		LogBackupImportedContext(adminserver.SessionContext, string, int64)
		LogBackupFailedContext(adminserver.SessionContext, string)
		LogBackupExportStartedContext(adminserver.SessionContext, string)
		LogBackupRestorePreviewedContext(adminserver.SessionContext, string, int)
		LogBackupRestorePreviewFailedContext(adminserver.SessionContext, string)
	}); !ok {
		t.Fatal("production audit does not satisfy identity/backup handler probes")
	}
	if _, ok := audit.(interface {
		LogCredentialRestoreIntentDurableContext(adminserver.SessionContext, string, string, bool) error
	}); !ok {
		t.Fatal("production audit does not satisfy durable credential-restore intent probe")
	}
	if _, ok := audit.(interface {
		LogCredentialRestoreContext(adminserver.SessionContext, adminproto.RestoreBackupResult)
		LogCredentialRestoreRollbackContext(adminserver.SessionContext, adminproto.RollbackRestoreResult)
	}); !ok {
		t.Fatal("production audit does not satisfy credential-restore outcome probes")
	}
}

func TestDurableCredentialRestoreIntentGate(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	svc := (&Signer{auditLog: auditLog}).adminServices()
	if err := svc.LogCredentialRestoreIntentDurableContext(
		adminserver.SessionContext{}, "restore-1", "backup.tar.gz", true,
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CREDENTIAL_RESTORE_INTENT") || !strings.Contains(string(data), "restore-1") {
		t.Fatalf("audit log missing durable restore intent: %q", data)
	}
	if err := (&Signer{}).adminServices().LogCredentialRestoreIntentDurableContext(
		adminserver.SessionContext{}, "restore-2", "backup.tar.gz", false,
	); err == nil {
		t.Fatal("missing audit logger did not fail closed")
	}
}
