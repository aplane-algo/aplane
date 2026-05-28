// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const (
	apstoreExitOK          = 0
	apstoreExitFailure     = 1
	apstoreExitUsage       = 2
	apstoreExitUnavailable = 3
	apstoreExitRateLimited = 4
	apstoreExitConflict    = 5
	apstoreExitArchive     = 6
)

type codedError struct {
	prefix  string
	code    string
	message string
}

func (e codedError) Error() string {
	switch {
	case e.prefix != "" && e.code != "" && e.message != "":
		return fmt.Sprintf("%s: %s: %s", e.prefix, e.code, e.message)
	case e.prefix != "" && e.message != "":
		return fmt.Sprintf("%s: %s", e.prefix, e.message)
	case e.code != "" && e.message != "":
		return fmt.Sprintf("%s: %s", e.code, e.message)
	case e.message != "":
		return e.message
	case e.prefix != "":
		return e.prefix
	default:
		return e.code
	}
}

func exitCodeForError(err error) int {
	if err == nil {
		return apstoreExitOK
	}
	var coded codedError
	if errors.As(err, &coded) {
		return exitCodeForResultCode(coded.code)
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.HasPrefix(msg, "usage:"),
		strings.Contains(msg, "invalid arguments"),
		strings.Contains(msg, "invalid config"),
		strings.Contains(msg, "destination directory unavailable"),
		strings.Contains(msg, "destination parent is not a directory"),
		strings.Contains(msg, "destination is not a directory"),
		strings.Contains(msg, "source must"),
		strings.Contains(msg, "destination must"):
		return apstoreExitUsage
	case strings.Contains(msg, "failed to connect to ipc socket"),
		strings.Contains(msg, "authentication failed"),
		strings.Contains(msg, "authorization denied"),
		strings.Contains(msg, "signer is locked"),
		strings.Contains(msg, "could not unlock"):
		return apstoreExitUnavailable
	case strings.Contains(msg, "rate_limited"):
		return apstoreExitRateLimited
	case strings.Contains(msg, "template_conflict"),
		strings.Contains(msg, "key_already_exists"),
		strings.Contains(msg, "provider collision"),
		strings.Contains(msg, "already registered as a built-in provider"),
		strings.Contains(msg, "key_type_in_use"),
		strings.Contains(msg, "key(s) still use it"):
		return apstoreExitConflict
	case strings.Contains(msg, "verification failed"),
		strings.Contains(msg, "failed to validate"),
		strings.Contains(msg, "failed to decrypt"),
		strings.Contains(msg, "unsupported backup"),
		strings.Contains(msg, "corrupt archive"),
		strings.Contains(msg, "checksum mismatch"),
		strings.Contains(msg, "size mismatch"):
		return apstoreExitArchive
	default:
		return apstoreExitFailure
	}
}

func exitCodeForResultCode(code string) int {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "":
		return apstoreExitFailure
	case protocol.ErrCodeAuthenticationFailed,
		protocol.ErrCodeInvalidPassphrase,
		protocol.ErrCodeUnlockFailed,
		protocol.ErrCodeAuthorizationDenied,
		protocol.ErrCodeSignerLocked,
		protocol.ErrCodeNoIdentityBound:
		return apstoreExitUnavailable
	case "restore_rate_limited":
		return apstoreExitRateLimited
	case "template_conflict",
		"key_already_exists",
		"provider_collision",
		"key_type_in_use",
		"activation_failed",
		"deactivation_failed",
		"remove_failed":
		return apstoreExitConflict
	case "verification_failed",
		"invalid_backup",
		"corrupt_archive",
		"bad_export_passphrase",
		"unsupported_backup_format",
		"decrypt_failed":
		return apstoreExitArchive
	case protocol.ErrCodeInvalidMessageFormat,
		protocol.ErrCodeInvalidAuthMessage,
		protocol.ErrCodeInvalidRequest,
		protocol.ErrCodeUnknownMessageType:
		return apstoreExitUsage
	default:
		return apstoreExitFailure
	}
}

func exitWithError(err error) {
	logErrorf("%v", err)
	osExit(exitCodeForError(err))
}

var osExit = func(code int) {
	os.Exit(code)
}
