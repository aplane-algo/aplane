// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
)

// stubAudit is an Audit that notes which of its methods ran, and for which
// session. Its durable
// intents are refused, as they are by a daemon with no audit log, unless
// durable is set. A test that looks at an entry embeds it and overrides the
// method that takes the entry.
type stubAudit struct {
	durable  bool
	calls    []string
	sessions []SessionContext
}

var _ Audit = (*stubAudit)(nil)

func (a *stubAudit) record(method string, ctx SessionContext) {
	a.calls = append(a.calls, method)
	a.sessions = append(a.sessions, ctx)
}

func (a *stubAudit) intent(method string, ctx SessionContext) error {
	a.record(method, ctx)
	if !a.durable {
		return ErrAuditUnavailable
	}
	return nil
}

func (a *stubAudit) LogAuthorizationDenied(ctx SessionContext, _ auth.Action, _ auth.Resource, _ string) {
	a.record("LogAuthorizationDenied", ctx)
}

func (a *stubAudit) LogAdminLoginFailedContext(ctx SessionContext, _ string) {
	a.record("LogAdminLoginFailedContext", ctx)
}

func (a *stubAudit) LogIdentityLockedContext(ctx SessionContext, _ string) {
	a.record("LogIdentityLockedContext", ctx)
}

func (a *stubAudit) LogSettingSaveErrorContext(ctx SessionContext, _ string, _ string, _ bool, _ string) {
	a.record("LogSettingSaveErrorContext", ctx)
}

func (a *stubAudit) LogPolicyApplyIntentDurableContext(ctx SessionContext, _ string, _ adminproto.ApplyPolicyRequest) error {
	return a.intent("LogPolicyApplyIntentDurableContext", ctx)
}

func (a *stubAudit) LogPolicyApplyResultContext(ctx SessionContext, _ string, _ adminproto.ApplyPolicyResult) {
	a.record("LogPolicyApplyResultContext", ctx)
}

func (a *stubAudit) LogASASetUpdateIntentDurableContext(ctx SessionContext, _ string, _ string, _ string, _ string, _ uint64) error {
	return a.intent("LogASASetUpdateIntentDurableContext", ctx)
}

func (a *stubAudit) LogASASetAddResultContext(ctx SessionContext, _ string, _ adminproto.AddASARequest, _ adminproto.AddASAResult) {
	a.record("LogASASetAddResultContext", ctx)
}

func (a *stubAudit) LogASASetRemoveResultContext(ctx SessionContext, _ string, _ adminproto.RemoveASARequest, _ adminproto.RemoveASAResult) {
	a.record("LogASASetRemoveResultContext", ctx)
}

func (a *stubAudit) LogSourceTokenChangeIntentDurableContext(ctx SessionContext, _ string, _ string, _ string, _ string) error {
	return a.intent("LogSourceTokenChangeIntentDurableContext", ctx)
}

func (a *stubAudit) LogSourceTokenChangeResultContext(ctx SessionContext, _ string, _ string, _ string, _ string, _ adminproto.SourceTokenChangeResult) {
	a.record("LogSourceTokenChangeResultContext", ctx)
}

func (a *stubAudit) LogCosignerReferenceChangedContext(ctx SessionContext, _ string, _ string, _ string, _ bool) {
	a.record("LogCosignerReferenceChangedContext", ctx)
}

func (a *stubAudit) LogKeyTypeChangedContext(ctx SessionContext, _ KeyTypeChange) {
	a.record("LogKeyTypeChangedContext", ctx)
}

func (a *stubAudit) LogBackupCreatedContext(ctx SessionContext, _ string) {
	a.record("LogBackupCreatedContext", ctx)
}

func (a *stubAudit) LogBackupImportedContext(ctx SessionContext, _ adminproto.CommitBackupImportResult) {
	a.record("LogBackupImportedContext", ctx)
}

func (a *stubAudit) LogBackupExportStartedContext(ctx SessionContext, _ string) {
	a.record("LogBackupExportStartedContext", ctx)
}

func (a *stubAudit) LogBackupFailedContext(ctx SessionContext, _ string) {
	a.record("LogBackupFailedContext", ctx)
}

func (a *stubAudit) LogBackupDeletedContext(ctx SessionContext, _ string, _ adminproto.DeleteBackupResult) {
	a.record("LogBackupDeletedContext", ctx)
}

func (a *stubAudit) LogBackupRestorePreviewedContext(ctx SessionContext, _ adminproto.RestorePreviewResult) {
	a.record("LogBackupRestorePreviewedContext", ctx)
}

func (a *stubAudit) LogBackupRestorePreviewFailedContext(ctx SessionContext, _ string) {
	a.record("LogBackupRestorePreviewFailedContext", ctx)
}

func (a *stubAudit) LogCredentialRestoreIntentDurableContext(ctx SessionContext, _ string, _ string, _ bool) error {
	return a.intent("LogCredentialRestoreIntentDurableContext", ctx)
}

func (a *stubAudit) LogCredentialRestoreContext(ctx SessionContext, _ adminproto.RestoreBackupResult) {
	a.record("LogCredentialRestoreContext", ctx)
}

func (a *stubAudit) LogCredentialRestoreRollbackContext(ctx SessionContext, _ adminproto.RollbackRestoreResult) {
	a.record("LogCredentialRestoreRollbackContext", ctx)
}

func (a *stubAudit) LogStoreReconciledContext(ctx SessionContext, _ adminproto.ReconcileStoreResult) {
	a.record("LogStoreReconciledContext", ctx)
}

func (a *stubAudit) LogGenerationQuarantinePruneIntentDurableContext(ctx SessionContext, _ string, _ []string) error {
	return a.intent("LogGenerationQuarantinePruneIntentDurableContext", ctx)
}

func (a *stubAudit) LogGenerationQuarantinePruneContext(ctx SessionContext, _ string, _ adminproto.PruneGenerationQuarantineResult) {
	a.record("LogGenerationQuarantinePruneContext", ctx)
}

func (a *stubAudit) LogGenerationAbandonedDiscardIntentDurableContext(ctx SessionContext, _ string, _ []string) error {
	return a.intent("LogGenerationAbandonedDiscardIntentDurableContext", ctx)
}

func (a *stubAudit) LogGenerationAbandonedDiscardContext(ctx SessionContext, _ string, _ adminproto.DiscardAbandonedGenerationsResult) {
	a.record("LogGenerationAbandonedDiscardContext", ctx)
}

func (a *stubAudit) LogDeletedArchivePruneIntentDurableContext(ctx SessionContext, _ string, _ []string) error {
	return a.intent("LogDeletedArchivePruneIntentDurableContext", ctx)
}

func (a *stubAudit) LogDeletedArchivePruneContext(ctx SessionContext, _ string, _ adminproto.PruneDeletedArchiveResult) {
	a.record("LogDeletedArchivePruneContext", ctx)
}
