// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"errors"
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

// CodeForError returns the code attached at the error origin, or
// ErrCodeInternal for an error that carries none.
func CodeForError(err error) string {
	if err == nil {
		return ""
	}
	var coded *CodedError
	if errors.As(err, &coded) && coded.Code != "" {
		return coded.Code
	}
	return ErrCodeInternal
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
	ErrCodeNoRuntimeBound       = "no_runtime_bound"
	ErrCodeAuthorizationDenied  = "authorization_denied"
	ErrCodeSignerLocked         = "signer_locked"
	ErrCodeKeyNotFound          = "key_not_found"
	ErrCodeNodeFailClosed       = "node_fail_closed"
	ErrCodeLoginTimeout         = "login_timeout"
	ErrCodeInternal             = "internal_error"
)

// Stable machine-readable result codes carried by admin result messages.
//
// These codes are result-local: they are not the central IPC error taxonomy
// above, but producers and CLI consumers still share them through this package
// so the lists cannot drift independently.
const (
	ResultCodeBackupFailed            = "backup_failed"
	ResultCodeListBackupsFailed       = "list_backups_failed"
	ResultCodeDeleteBackupFailed      = "delete_backup_failed"
	ResultCodeRestorePreviewFailed    = "restore_preview_failed"
	ResultCodeRestoreRateLimited      = "restore_rate_limited"
	ResultCodeRestoreFailed           = "restore_failed"
	ResultCodeRestoreConflict         = "restore_conflict"
	ResultCodeRestoreRollbackFailed   = "restore_rollback_failed"
	ResultCodeRestoreRollbackRefused  = "restore_rollback_refused"
	ResultCodeRestoreRollbackDiverged = "restore_rollback_diverged"
	ResultCodeRestoreAuditFailed      = "restore_audit_failed"
	ResultCodeQuarantinePruneFailed   = "quarantine_prune_failed"
	ResultCodeAbandonedDiscardFailed  = "abandoned_discard_failed"
	ResultCodeAbandonedAuditFailed    = "abandoned_discard_audit_failed"
	ResultCodeQuarantineAuditFailed   = "quarantine_audit_failed"
	ResultCodeArchiveListFailed       = "archive_list_failed"
	ResultCodeArchivePruneFailed      = "archive_prune_failed"
	ResultCodeArchiveAuditFailed      = "archive_audit_failed"
	// ResultCodeAuditUnavailable refuses a policy or ASA set change because
	// the daemon has no audit log (it could not be opened at startup);
	// ResultCodeAuditWriteFailed because the request's intent could not be
	// recorded in it.
	ResultCodeAuditUnavailable     = "audit_unavailable"
	ResultCodeAuditWriteFailed     = "audit_write_failed"
	ResultCodeConfirmationRequired = "confirmation_required"
	// ResultCodeRecoveryBlocked reports a signer left in recovery mode, with
	// signing blocked until the operator resolves the store from recovery:
	// an unlock that succeeded into it (success:true — the passphrase was
	// right, but the store failed reconciliation or generation validation, or
	// the reload its publish ran entered it), a key or template change that
	// was written and whose reload then entered it (for a content defect in
	// the selected generation or a store root that no longer authenticates),
	// or a restore or rollback that committed (or completed as a recovery
	// no-op) whose reload or post-commit recovery-exit rescan left the signer
	// in recovery (success:false, with any committed generation still
	// selected).
	ResultCodeRecoveryBlocked = "recovery_blocked"
	// ResultCodePassphraseChangeFailed reports a change_store_passphrase
	// that failed for a reason other than its passphrases, including a store
	// root or selected generation that cannot be opened.
	ResultCodePassphraseChangeFailed = "passphrase_change_failed"
	// ResultCodePassphraseHelperError reports an initialize or passphrase
	// change refused because the unlock.yaml passphrase helper configuration
	// could not be loaded.
	ResultCodePassphraseHelperError = "passphrase_helper_error"
	// ResultCodeAppliedNotSaved reports a failed result whose change is in
	// effect but was not saved at all: the save failed before the new file
	// replaced the old one, so the next start loads the old value.
	ResultCodeAppliedNotSaved = "applied_not_saved"

	ResultCodeStoreBusy            = "store_busy"
	ResultCodeListFailed           = "list_failed"
	ResultCodeNotFound             = "not_found"
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

	// Policy results.
	ResultCodeExpectedPolicySetSHA256Required = "expected_policy_set_sha256_required"
	ResultCodeExpectedSnapshotSHA256Required  = "expected_snapshot_sha256_required"
	ResultCodePolicyUnavailable               = "policy_unavailable"
	ResultCodeInvalidPolicyRequest            = "invalid_policy_request"
	ResultCodePolicySetTooLarge               = "policy_set_too_large"
	ResultCodePolicyContextUnavailable        = "policy_context_unavailable"
	ResultCodePolicyCheckFailed               = "policy_check_failed"
	ResultCodePolicyVerifyFailed              = "policy_verify_failed"
	ResultCodePolicySnapshotChanged           = "policy_snapshot_changed"
	ResultCodePolicyValidationFailed          = "policy_validation_failed"
	ResultCodePolicyCommitUncertain           = "policy_commit_uncertain"
	ResultCodePolicySaveFailed                = "policy_save_failed"
	ResultCodePolicyApplyFailed               = "policy_apply_failed"
	ResultCodePolicyReloadFailed              = "policy_reload_failed"
	ResultCodePolicyDocumentNotFound          = "policy_document_not_found"
	ResultCodePolicyExportStale               = "policy_export_stale"

	// ASA set results.
	ResultCodeASAUnknownNetwork    = "unknown_network"
	ResultCodeASALookupFailed      = "lookup_failed"
	ResultCodeASAConfirmationStale = "confirmation_stale"
	ResultCodeASABuiltin           = "asa_builtin"
	ResultCodeASAAlreadyConfirmed  = "asa_already_confirmed"
	ResultCodeASAReferenced        = "asa_referenced"
	ResultCodeASAAddFailed         = "asa_add_failed"
	ResultCodeASARemoveFailed      = "asa_remove_failed"
	ResultCodeASACommitUncertain   = "asa_commit_uncertain"
	ResultCodeASAReloadFailed      = "asa_reload_failed"
)
