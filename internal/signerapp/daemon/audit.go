// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"

type AuditEventType = signeraudit.AuditEventType
type AuditEntry = signeraudit.AuditEntry
type AuditLogger = signeraudit.AuditLogger

type auditAttribution = signeraudit.Attribution

const (
	AuditSignRequest                = signeraudit.AuditSignRequest
	AuditSignApproved               = signeraudit.AuditSignApproved
	AuditSignRejected               = signeraudit.AuditSignRejected
	AuditSignFailed                 = signeraudit.AuditSignFailed
	AuditAuthFailed                 = signeraudit.AuditAuthFailed
	AuditAuthorizationDenied        = signeraudit.AuditAuthorizationDenied
	AuditServerStart                = signeraudit.AuditServerStart
	AuditServerStop                 = signeraudit.AuditServerStop
	AuditKeyReload                  = signeraudit.AuditKeyReload
	AuditSessionConnected           = signeraudit.AuditSessionConnected
	AuditSessionDisconnected        = signeraudit.AuditSessionDisconnected
	AuditIdentityLocked             = signeraudit.AuditIdentityLocked
	AuditTokenProvisioned           = signeraudit.AuditTokenProvisioned
	AuditKeyGenerated               = signeraudit.AuditKeyGenerated
	AuditKeyDeleted                 = signeraudit.AuditKeyDeleted
	AuditKeyImported                = signeraudit.AuditKeyImported
	AuditKeyRejected                = signeraudit.AuditKeyRejected
	AuditBackupCreated              = signeraudit.AuditBackupCreated
	AuditBackupFailed               = signeraudit.AuditBackupFailed
	AuditBackupRestorePreviewed     = signeraudit.AuditBackupRestorePreviewed
	AuditBackupRestorePreviewFailed = signeraudit.AuditBackupRestorePreviewFailed
	AuditBackupRestoreStarted       = signeraudit.AuditBackupRestoreStarted
	AuditBackupRestoreCompleted     = signeraudit.AuditBackupRestoreCompleted
	AuditBackupRestorePartial       = signeraudit.AuditBackupRestorePartial
	AuditBackupRestoreFailed        = signeraudit.AuditBackupRestoreFailed
	AuditStoreInitialized           = signeraudit.AuditStoreInitialized
	AuditStoreInitializeFailed      = signeraudit.AuditStoreInitializeFailed
	AuditPassphraseChanged          = signeraudit.AuditPassphraseChanged
	AuditPassphraseChangeFailed     = signeraudit.AuditPassphraseChangeFailed
)

func NewAuditLogger(path string) (*AuditLogger, error) {
	return signeraudit.NewAuditLogger(path)
}
