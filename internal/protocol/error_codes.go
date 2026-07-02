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
// falling back to deriving one from the message text for legacy paths.
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
	ResultCodeBackupFailed             = "backup_failed"
	ResultCodeListBackupsFailed        = "list_backups_failed"
	ResultCodeDeleteBackupFailed       = "delete_backup_failed"
	ResultCodeRestorePreviewFailed     = "restore_preview_failed"
	ResultCodeRestoreRateLimited       = "restore_rate_limited"
	ResultCodeInvalidBackupArchive     = "invalid_backup_archive"
	ResultCodeBackupArchiveNotFound    = "backup_archive_not_found"
	ResultCodeBackupArchiveUnavailable = "backup_archive_unavailable"
	ResultCodePrepareRestoreFailed     = "prepare_restore_failed"
	ResultCodeScanBackupFailed         = "scan_backup_failed"
	ResultCodeEmptyBackup              = "empty_backup"

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

// IPCErrorCode derives a stable machine-readable code from an existing
// human-readable protocol/admin error string.
func IPCErrorCode(errMsg string) string {
	errMsg = strings.TrimSpace(errMsg)
	if errMsg == "" {
		return ""
	}

	lower := strings.ToLower(errMsg)
	switch {
	case lower == "invalid message format":
		return ErrCodeInvalidMessageFormat
	case lower == "expected auth message":
		return ErrCodeExpectedAuthMessage
	case lower == "invalid auth message format":
		return ErrCodeInvalidAuthMessage
	case lower == "authentication failed":
		return ErrCodeAuthenticationFailed
	case lower == "invalid passphrase", lower == "incorrect passphrase":
		return ErrCodeInvalidPassphrase
	case strings.HasPrefix(lower, "auth ok but unlock failed:"),
		strings.HasPrefix(lower, "failed to load keys:"):
		return ErrCodeUnlockFailed
	case lower == "invalid generate key message",
		lower == "invalid import key message",
		lower == "invalid export key message",
		lower == "invalid delete key message",
		lower == "invalid list keys message",
		lower == "invalid unlock message",
		lower == "invalid key details message",
		strings.HasPrefix(lower, "unknown or read-only setting:"):
		return ErrCodeInvalidRequest
	case strings.HasPrefix(lower, "unknown message type:"):
		return ErrCodeUnknownMessageType
	case lower == "no identity bound to session":
		return ErrCodeNoIdentityBound
	case lower == "authorization denied":
		return ErrCodeAuthorizationDenied
	case lower == "signer is locked":
		return ErrCodeSignerLocked
	case strings.HasPrefix(lower, "key not found:"):
		return ErrCodeKeyNotFound
	default:
		return ErrCodeInternal
	}
}
