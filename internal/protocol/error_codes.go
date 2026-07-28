// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"errors"
	"strings"
)

// CodedError carries a stable IPC error code attached at the error origin.
// Adapters should classify errors with CodeForError instead of matching
// message text.
type CodedError struct {
	Code string
	Err  error
}

func (e *CodedError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *CodedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// WithCode attaches a stable IPC error code to err at its origin.
func WithCode(code string, err error) error {
	if err == nil {
		return nil
	}
	return &CodedError{Code: code, Err: err}
}

// CodeForError returns the code attached at the error origin when present,
// falling back to exact legacy message strings for old codeless peers.
func CodeForError(err error) string {
	if err == nil {
		return ""
	}
	var coded *CodedError
	if errors.As(err, &coded) && coded.Code != "" {
		return coded.Code
	}
	return IPCErrorCode(err.Error())
}

// Stable machine-readable IPC/admin error codes.
const (
	ErrCodeInvalidMessageFormat = "invalid_message_format"
	ErrCodeExpectedAuthMessage  = "expected_auth_message"
	ErrCodeInvalidAuthMessage   = "invalid_auth_message"
	ErrCodeAuthenticationFailed = "authentication_failed"
	ErrCodeInvalidPassphrase    = "invalid_passphrase"
	ErrCodeUnlockFailed         = "unlock_failed"
	ErrCodeInvalidRequest       = "invalid_request"
	ErrCodeUnknownMessageType   = "unknown_message_type"
	ErrCodeNoIdentityBound      = "no_identity_bound"
	ErrCodeAuthorizationDenied  = "authorization_denied"
	ErrCodeSignerLocked         = "signer_locked"
	ErrCodeKeyNotFound          = "key_not_found"
	ErrCodeInternal             = "internal_error"
)

// Stable machine-readable result codes carried by admin result messages.
//
// These codes are result-local: they are not the central IPC error taxonomy
// above, but producers and CLI consumers still share them through this package
// so the lists cannot drift independently.
const (
	ResultCodeBackupFailed              = "backup_failed"
	ResultCodeListBackupsFailed         = "list_backups_failed"
	ResultCodeDeleteBackupFailed        = "delete_backup_failed"
	ResultCodeRestorePreviewFailed      = "restore_preview_failed"
	ResultCodeRestoreRateLimited        = "restore_rate_limited"
	ResultCodeInvalidBackupArchive      = "invalid_backup_archive"
	ResultCodeBackupArchiveNotFound     = "backup_archive_not_found"
	ResultCodeBackupArchiveUnavailable  = "backup_archive_unavailable"
	ResultCodePrepareRestoreFailed      = "prepare_restore_failed"
	ResultCodeScanBackupFailed          = "scan_backup_failed"
	ResultCodeEmptyBackup               = "empty_backup"
	ResultCodeRecoverBackupFailed       = "recover_backup_failed"
	ResultCodeListRecoveredFailed       = "list_recovered_failed"
	ResultCodeReviewRecoveredFailed     = "review_recovered_failed"
	ResultCodeActivationReviewStale     = "activation_review_stale"
	ResultCodeActivationAckRequired     = "activation_acknowledgement_required"
	ResultCodeActivationConflict        = "activation_conflict"
	ResultCodeRecoveredActivationFailed = "recovered_activation_failed"
	ResultCodeRecoveredRollbackFailed   = "recovered_rollback_failed"
	// ResultCodeRecoveredRollbackRefused reports a rollback the server
	// refused before mutating anything: no recovery mode was entered and
	// the store is unchanged. Clients must not treat it as evidence of
	// recovery (recovered_rollback_failed means state was mutated and the
	// failure forced recovery).
	ResultCodeRecoveredRollbackRefused = "recovered_rollback_refused"
	// ResultCodeRecoveredRollbackDiverged reports a rollback the server
	// refused because the current generation no longer matches its at-mint
	// inventory: the store was mutated after the activation (a generated
	// key, an installed template), and repointing CURRENT at the parent
	// would discard those later changes. Nothing was mutated and no
	// recovery mode was entered.
	ResultCodeRecoveredRollbackDiverged = "recovered_rollback_diverged"
	ResultCodePurgeRecoveredFailed      = "purge_recovered_failed"
	// ResultCodeRecoveryBlocked reports an unlock that succeeded into
	// recovery mode: the passphrase was right, but the store failed
	// reconciliation or generation validation, so signing is blocked until
	// the operator resolves the store from recovery.
	ResultCodeRecoveryBlocked       = "recovery_blocked"
	ResultCodeActivationAuditFailed = "activation_audit_failed"

	ResultCodeListFailed           = "list_failed"
	ResultCodeInvalidTemplateType  = "invalid_template_type"
	ResultCodeInstallFailed        = "install_failed"
	ResultCodeReloadFailed         = "reload_failed"
	ResultCodeActivationFailed     = "activation_failed"
	ResultCodeLibraryReadFailed    = "library_read_failed"
	ResultCodeLibraryEntryNotFound = "library_entry_not_found"
	ResultCodeTemplateStateFailed  = "template_state_failed"
	ResultCodeTemplateNotFound     = "template_not_found"
	ResultCodeDecryptFailed        = "decrypt_failed"
	ResultCodeInvalidTemplate      = "invalid_template"
	ResultCodeImportFailed         = "import_failed"
	ResultCodeRemoveFailed         = "remove_failed"
	ResultCodeKeyTypeInUse         = "key_type_in_use"
	ResultCodeDeactivationFailed   = "deactivation_failed"
)

// IPCErrorCode maps the small set of legacy codeless protocol/admin messages
// whose exact text shipped before the wire carried explicit codes. New code
// must attach codes at the source with WithCode instead of adding message-text
// patterns here.
func IPCErrorCode(errMsg string) string {
	errMsg = strings.TrimSpace(errMsg)
	if errMsg == "" {
		return ""
	}

	lower := strings.ToLower(errMsg)
	switch lower {
	case "invalid message format":
		return ErrCodeInvalidMessageFormat
	case "expected auth message":
		return ErrCodeExpectedAuthMessage
	case "invalid auth message format":
		return ErrCodeInvalidAuthMessage
	case "authentication failed":
		return ErrCodeAuthenticationFailed
	case "invalid passphrase", "incorrect passphrase":
		return ErrCodeInvalidPassphrase
	case "invalid generate key message",
		"invalid import key message",
		"invalid export key message",
		"invalid delete key message",
		"invalid list keys message",
		"invalid unlock message",
		"invalid key details message":
		return ErrCodeInvalidRequest
	case "no identity bound to session":
		return ErrCodeNoIdentityBound
	case "authorization denied":
		return ErrCodeAuthorizationDenied
	case "signer is locked":
		return ErrCodeSignerLocked
	default:
		return ErrCodeInternal
	}
}
