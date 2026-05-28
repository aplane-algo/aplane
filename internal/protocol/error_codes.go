// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import "strings"

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
