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
// durable restore-intent gate, silently disarms a contract-required
// precondition). TestAdminSessionAuditSatisfiesHandlerProbes pins the full
// probe set against this type.

func (s signerAdminServices) auditLogger() *AuditLogger {
	if s.signer == nil {
		return nil
	}
	return s.signer.auditLog
}

func (s signerAdminServices) LogCredentialRestoreIntentDurableContext(
	ctx adminserver.SessionContext,
	operationID, archivePath string,
	replaceExisting bool,
) error {
	audit := s.auditLogger()
	if audit == nil {
		return fmt.Errorf("audit log unavailable; refusing restore without a durable intent record")
	}
	return audit.LogCredentialRestoreIntentDurableContext(
		ctx, operationID, archivePath, replaceExisting,
	)
}

func (s signerAdminServices) LogCredentialRestoreContext(
	ctx adminserver.SessionContext,
	result adminproto.RestoreBackupResult,
) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogCredentialRestoreContext(ctx, result)
	}
}

func (s signerAdminServices) LogCredentialRestoreRollbackContext(
	ctx adminserver.SessionContext,
	result adminproto.RollbackRestoreResult,
) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogCredentialRestoreRollbackContext(ctx, result)
	}
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
