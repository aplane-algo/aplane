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
		return fmt.Errorf("%w; refusing restore without a durable intent record", adminserver.ErrAuditUnavailable)
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

func (s signerAdminServices) LogGenerationQuarantinePruneIntentDurableContext(
	ctx adminserver.SessionContext,
	operationID string,
	generationIDs []string,
) error {
	audit := s.auditLogger()
	if audit == nil {
		return fmt.Errorf("%w; refusing quarantine prune without a durable intent record", adminserver.ErrAuditUnavailable)
	}
	return audit.LogGenerationQuarantinePruneIntentDurableContext(ctx, operationID, generationIDs)
}

func (s signerAdminServices) LogGenerationQuarantinePruneContext(
	ctx adminserver.SessionContext,
	operationID string,
	result adminproto.PruneGenerationQuarantineResult,
) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogGenerationQuarantinePruneContext(ctx, operationID, result)
	}
}

func (s signerAdminServices) LogGenerationAbandonedDiscardIntentDurableContext(
	ctx adminserver.SessionContext,
	operationID string,
	generationIDs []string,
) error {
	audit := s.auditLogger()
	if audit == nil {
		return fmt.Errorf("%w; refusing abandoned discard without a durable intent record", adminserver.ErrAuditUnavailable)
	}
	return audit.LogGenerationAbandonedDiscardIntentDurableContext(ctx, operationID, generationIDs)
}

func (s signerAdminServices) LogGenerationAbandonedDiscardContext(
	ctx adminserver.SessionContext,
	operationID string,
	result adminproto.DiscardAbandonedGenerationsResult,
) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogGenerationAbandonedDiscardContext(ctx, operationID, result)
	}
}

func (s signerAdminServices) LogDeletedArchivePruneIntentDurableContext(
	ctx adminserver.SessionContext,
	operationID string,
	entries []string,
) error {
	audit := s.auditLogger()
	if audit == nil {
		return fmt.Errorf("%w; refusing archive prune without a durable intent record", adminserver.ErrAuditUnavailable)
	}
	return audit.LogDeletedArchivePruneIntentDurableContext(ctx, operationID, entries)
}

func (s signerAdminServices) LogDeletedArchivePruneContext(
	ctx adminserver.SessionContext,
	operationID string,
	result adminproto.PruneDeletedArchiveResult,
) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogDeletedArchivePruneContext(ctx, operationID, result)
	}
}

func (s signerAdminServices) LogBackupCreatedContext(ctx adminserver.SessionContext, archivePath string) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupCreatedContext(ctx, archivePath)
	}
}

func (s signerAdminServices) LogBackupImportedContext(ctx adminserver.SessionContext, fileName string, size int64) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupImportedContext(ctx, fileName, size)
	}
}

func (s signerAdminServices) LogBackupExportStartedContext(ctx adminserver.SessionContext, fileName string) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogBackupExportStartedContext(ctx, fileName)
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

func (s signerAdminServices) LogCosignerReferenceChangedContext(ctx adminserver.SessionContext, action, name, componentKey string, success bool) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogCosignerReferenceChangedContext(ctx, action, name, componentKey, success)
	}
}

// Live policy and ASA set changes. A missing logger is ErrAuditUnavailable,
// so the handler tells the operator a restart is needed, not a retry.

func (s signerAdminServices) LogPolicyApplyIntentDurableContext(
	ctx adminserver.SessionContext,
	operationID string,
	req adminproto.ApplyPolicyRequest,
) error {
	audit := s.auditLogger()
	if audit == nil {
		return adminserver.ErrAuditUnavailable
	}
	return audit.LogPolicyApplyIntentDurableContext(ctx, operationID, req)
}

func (s signerAdminServices) LogPolicyApplyResultContext(
	ctx adminserver.SessionContext,
	operationID string,
	result adminproto.ApplyPolicyResult,
) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogPolicyApplyResultContext(ctx, operationID, result)
	}
}

func (s signerAdminServices) LogASASetUpdateIntentDurableContext(
	ctx adminserver.SessionContext,
	operationID, action, network, genesisHash string,
	assetID uint64,
) error {
	audit := s.auditLogger()
	if audit == nil {
		return adminserver.ErrAuditUnavailable
	}
	return audit.LogASASetUpdateIntentDurableContext(ctx, operationID, action, network, genesisHash, assetID)
}

func (s signerAdminServices) LogASASetAddResultContext(
	ctx adminserver.SessionContext,
	operationID string,
	req adminproto.AddASARequest,
	result adminproto.AddASAResult,
) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogASASetAddResultContext(ctx, operationID, req, result)
	}
}

func (s signerAdminServices) LogASASetRemoveResultContext(
	ctx adminserver.SessionContext,
	operationID string,
	req adminproto.RemoveASARequest,
	result adminproto.RemoveASAResult,
) {
	if audit := s.auditLogger(); audit != nil {
		audit.LogASASetRemoveResultContext(ctx, operationID, req, result)
	}
}
