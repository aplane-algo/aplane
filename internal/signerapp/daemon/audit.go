// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollment"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/signerapp/storeadmin"
)

type AuditEventType = signeraudit.AuditEventType
type AuditEntry = signeraudit.AuditEntry
type AuditLogger = signeraudit.AuditLogger

type auditAttribution = signeraudit.Attribution

const (
	AuditSignRequest                      = signeraudit.AuditSignRequest
	AuditPlanRequest                      = signeraudit.AuditPlanRequest
	AuditSignApproved                     = signeraudit.AuditSignApproved
	AuditSignRejected                     = signeraudit.AuditSignRejected
	AuditSignFailed                       = signeraudit.AuditSignFailed
	AuditAuthFailed                       = signeraudit.AuditAuthFailed
	AuditAuthorizationDenied              = signeraudit.AuditAuthorizationDenied
	AuditServerStart                      = signeraudit.AuditServerStart
	AuditServerStop                       = signeraudit.AuditServerStop
	AuditServerStopIncomplete             = signeraudit.AuditServerStopIncomplete
	AuditKeyReload                        = signeraudit.AuditKeyReload
	AuditSessionConnected                 = signeraudit.AuditSessionConnected
	AuditSessionDisconnected              = signeraudit.AuditSessionDisconnected
	AuditIdentityLocked                   = signeraudit.AuditIdentityLocked
	AuditClientEnrollmentRequested        = signeraudit.AuditClientEnrollmentRequested
	AuditClientEnrolled                   = signeraudit.AuditClientEnrolled
	AuditClientEnrollmentRejected         = signeraudit.AuditClientEnrollmentRejected
	AuditKeyGenerated                     = signeraudit.AuditKeyGenerated
	AuditKeyDeleted                       = signeraudit.AuditKeyDeleted
	AuditKeyImported                      = signeraudit.AuditKeyImported
	AuditKeyRejected                      = signeraudit.AuditKeyRejected
	AuditBackupCreated                    = signeraudit.AuditBackupCreated
	AuditBackupFailed                     = signeraudit.AuditBackupFailed
	AuditBackupRestorePreviewed           = signeraudit.AuditBackupRestorePreviewed
	AuditBackupRestorePreviewFailed       = signeraudit.AuditBackupRestorePreviewFailed
	AuditCredentialRestoreIntent          = signeraudit.AuditCredentialRestoreIntent
	AuditCredentialRestoreSuccess         = signeraudit.AuditCredentialRestoreSuccess
	AuditCredentialRestoreFailed          = signeraudit.AuditCredentialRestoreFailed
	AuditCredentialRestoreUncertain       = signeraudit.AuditCredentialRestoreUncertain
	AuditCredentialRestoreRollback        = signeraudit.AuditCredentialRestoreRollback
	AuditStoreInitialized                 = signeraudit.AuditStoreInitialized
	AuditStoreInitializeFailed            = signeraudit.AuditStoreInitializeFailed
	AuditPassphraseChanged                = signeraudit.AuditPassphraseChanged
	AuditPassphraseChangeFailed           = signeraudit.AuditPassphraseChangeFailed
	AuditCosignerReferenceChanged         = signeraudit.AuditCosignerReferenceChanged
	AuditBackupImported                   = signeraudit.AuditBackupImported
	AuditBackupExportStarted              = signeraudit.AuditBackupExportStarted
	AuditGenerationQuarantineIntent       = signeraudit.AuditGenerationQuarantineIntent
	AuditGenerationQuarantined            = signeraudit.AuditGenerationQuarantined
	AuditGenerationQuarantinePruneIntent  = signeraudit.AuditGenerationQuarantinePruneIntent
	AuditGenerationQuarantinePruned       = signeraudit.AuditGenerationQuarantinePruned
	AuditGenerationAbandonedDiscardIntent = signeraudit.AuditGenerationAbandonedDiscardIntent
	AuditGenerationAbandonedDiscarded     = signeraudit.AuditGenerationAbandonedDiscarded
	AuditDeletedArchivePruneIntent        = signeraudit.AuditDeletedArchivePruneIntent
	AuditDeletedArchivePruned             = signeraudit.AuditDeletedArchivePruned
)

func NewAuditLogger(path string) (*AuditLogger, error) {
	return signeraudit.NewAuditLogger(path)
}

// optionalAuditLog returns log as the audit interface I a service takes, or
// I's nil when the daemon runs without an audit log (audit.log could not be
// opened at startup). Every service gets its logger through here: a nil
// *AuditLogger assigned to an interface makes a non-nil interface, so the
// service's `!= nil` guards pass and its first entry panics.
func optionalAuditLog[I any](log *AuditLogger) I {
	var sink I
	if log != nil {
		sink = any(log).(I)
	}
	return sink
}

// The interfaces the daemon passes through optionalAuditLog. Listing them
// here makes a method dropped from *AuditLogger fail the build rather than
// the type assertion at run time.
var (
	_ keyadmin.AuditLogger            = (*AuditLogger)(nil)
	_ enrollment.AuditLogger          = (*AuditLogger)(nil)
	_ storeadmin.AuditLogger          = (*AuditLogger)(nil)
	_ signerstartup.ServerAuditLogger = (*AuditLogger)(nil)
)
