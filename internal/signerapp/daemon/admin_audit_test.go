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

// TestAdminSessionAuditSatisfiesHandlerProbes pins the production audit
// wiring against every interface the admin session handlers probe on
// SessionDeps.Audit. The handlers discover audit capabilities dynamically,
// so a missing forwarder on signerAdminServices does not fail any build —
// it silently drops the event family in the production daemon and, for the
// durable activation-intent gate, disarms a contract-required precondition.
// Each interface below must mirror its probe in adminserver/handlers.go.
func TestAdminSessionAuditSatisfiesHandlerProbes(t *testing.T) {
	server := &Signer{}
	audit := server.adminSessionDeps().Audit

	if _, ok := audit.(interface {
		LogBackupActivationIntentDurableContext(adminserver.SessionContext, string, bool) error
	}); !ok {
		t.Fatal("production Audit does not satisfy the durable activation-intent gate probe (HandleActivateRecovered)")
	}
	if _, ok := audit.(interface {
		LogIdentityLockedContext(adminserver.SessionContext, string)
	}); !ok {
		t.Fatal("production Audit does not satisfy the identity-locked probe")
	}
	if _, ok := audit.(interface {
		LogBackupCreatedContext(adminserver.SessionContext, string)
		LogBackupFailedContext(adminserver.SessionContext, string)
	}); !ok {
		t.Fatal("production Audit does not satisfy the backup created/failed probe")
	}
	if _, ok := audit.(interface {
		LogBackupRestorePreviewedContext(adminserver.SessionContext, string, int)
		LogBackupRestorePreviewFailedContext(adminserver.SessionContext, string)
	}); !ok {
		t.Fatal("production Audit does not satisfy the restore-preview probe")
	}
	if _, ok := audit.(interface {
		LogBackupRecoveredContext(adminserver.SessionContext, adminproto.RecoverBackupResult)
		LogBackupRecoveryFailedContext(adminserver.SessionContext, string, string)
	}); !ok {
		t.Fatal("production Audit does not satisfy the recovered/recovery-failed probe")
	}
	if _, ok := audit.(interface {
		LogBackupActivatedContext(adminserver.SessionContext, adminproto.ActivateRecoveredResult)
		LogBackupActivationFailedContext(adminserver.SessionContext, adminproto.ActivateRecoveredResult)
		LogBackupActivationResumedContext(adminserver.SessionContext, adminproto.ActivateRecoveredResult)
	}); !ok {
		t.Fatal("production Audit does not satisfy the activation outcome probe")
	}
	if _, ok := audit.(interface {
		LogBackupActivationRolledBackContext(adminserver.SessionContext, adminproto.RollbackRecoveredResult)
	}); !ok {
		t.Fatal("production Audit does not satisfy the rollback probe")
	}
	if _, ok := audit.(interface {
		LogBackupRecoveryPurgedContext(adminserver.SessionContext, adminproto.PurgeRecoveredResult)
	}); !ok {
		t.Fatal("production Audit does not satisfy the recovery-purged probe")
	}
}

func TestDurableActivationIntentGate(t *testing.T) {
	t.Run("records durably through the production wiring", func(t *testing.T) {
		auditPath := filepath.Join(t.TempDir(), "audit.log")
		auditLog, err := NewAuditLogger(auditPath)
		if err != nil {
			t.Fatalf("NewAuditLogger: %v", err)
		}
		defer func() { _ = auditLog.Close() }()
		server := &Signer{auditLog: auditLog}
		svc := server.adminServices()

		if err := svc.LogBackupActivationIntentDurableContext(adminserver.SessionContext{}, "restore-1", true); err != nil {
			t.Fatalf("durable intent gate error = %v, want recorded", err)
		}
		data, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		if !strings.Contains(string(data), "BACKUP_ACTIVATION_INTENT") || !strings.Contains(string(data), "restore-1") {
			t.Fatalf("audit log missing durable intent record: %q", string(data))
		}
	})

	t.Run("fails closed without an audit log", func(t *testing.T) {
		svc := (&Signer{}).adminServices()
		if err := svc.LogBackupActivationIntentDurableContext(adminserver.SessionContext{}, "restore-1", false); err == nil {
			t.Fatal("durable intent gate succeeded with no audit log; activation would proceed unrecorded")
		}
	})
}
