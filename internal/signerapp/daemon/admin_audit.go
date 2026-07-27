// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// signerAdminServices is what production wires as adminserver.SessionDeps.Audit,
// and the admin session handlers discover audit capabilities by interface
// probe. Every probed method must therefore be forwarded here: a missing
// forwarder does not fail a build or a test with a fake audit sink — it
// silently drops the event family in the production daemon (and, for the
// durable activation-intent gate, silently disarms a contract-required
// precondition). TestAdminSessionAuditSatisfiesHandlerProbes pins the full
// probe set against this type.

func (s signerAdminServices) auditLogger() *AuditLogger {
	if s.signer == nil {
		return nil
	}
	return s.signer.auditLog
}

// LogBackupActivationIntentDurableContext is the activation gate:
// BACKUP_ACTIVATION_INTENT must be durable before the first active-store
// write (ARCH_CONTRACTS), so an unavailable audit log fails closed instead
// of proceeding unrecorded.
func (s signerAdminServices) LogBackupActivationIntentDurableContext(ctx adminserver.SessionContext, restoreID string, replaceExisting bool) error {
	audit := s.auditLogger()
	if audit == nil {
		return fmt.Errorf("audit log unavailable; refusing activation without a durable intent record")
	}
	return audit.LogBackupActivationIntentDurableContext(ctx, restoreID, replaceExisting)
}

func (s signerAdminServices) LogIdentityLockedContext(ctx adminserver.SessionContext, reason string) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogIdentityLockedContext(ctx, reason)
	}
}

func (s signerAdminServices) LogBackupCreatedContext(ctx adminserver.SessionContext, archivePath string) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupCreatedContext(ctx, archivePath)
	}
}

func (s signerAdminServices) LogBackupFailedContext(ctx adminserver.SessionContext, reason string) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupFailedContext(ctx, reason)
	}
}

func (s signerAdminServices) LogBackupRestorePreviewedContext(ctx adminserver.SessionContext, archivePath string, keyCount int) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupRestorePreviewedContext(ctx, archivePath, keyCount)
	}
}

func (s signerAdminServices) LogBackupRestorePreviewFailedContext(ctx adminserver.SessionContext, reason string) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupRestorePreviewFailedContext(ctx, reason)
	}
}

func (s signerAdminServices) LogBackupRecoveredContext(ctx adminserver.SessionContext, result adminproto.RecoverBackupResult) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupRecoveredContext(ctx, result)
	}
}

func (s signerAdminServices) LogBackupRecoveryFailedContext(ctx adminserver.SessionContext, restoreID, reason string) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupRecoveryFailedContext(ctx, restoreID, reason)
	}
}

func (s signerAdminServices) LogBackupActivationIntentContext(ctx adminserver.SessionContext, restoreID string, replaceExisting bool) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupActivationIntentContext(ctx, restoreID, replaceExisting)
	}
}

func (s signerAdminServices) LogBackupActivatedContext(ctx adminserver.SessionContext, result adminproto.ActivateRecoveredResult) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupActivatedContext(ctx, result)
	}
}

func (s signerAdminServices) LogBackupActivationFailedContext(ctx adminserver.SessionContext, result adminproto.ActivateRecoveredResult) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupActivationFailedContext(ctx, result)
	}
}

func (s signerAdminServices) LogBackupActivationRolledBackContext(ctx adminserver.SessionContext, result adminproto.RollbackRecoveredResult) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupActivationRolledBackContext(ctx, result)
	}
}

func (s signerAdminServices) LogBackupRecoveryPurgedContext(ctx adminserver.SessionContext, result adminproto.PurgeRecoveredResult) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupRecoveryPurgedContext(ctx, result)
	}
}
