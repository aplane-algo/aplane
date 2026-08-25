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

// policyIntegrityFailedCode classifies policy document integrity failures.
// It maps to the generic failure exit code rather than the archive code the
// old substring fallback misrouted these errors to.
const policyIntegrityFailedCode = "policy_integrity_failed"

const apstoreCodeIPCUnavailable = "ipc_unavailable"

type codedError struct {
	prefix  string
	code    string
	message string
}

func resultError(prefix, code, message string) error {
	if message == "" {
		message = "operation failed"
	}
	return codedError{prefix: prefix, code: code, message: message}
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
	var protocolCoded *protocol.CodedError
	if errors.As(err, &protocolCoded) {
		return exitCodeForResultCode(protocolCoded.Code)
	}

	msg := strings.ToLower(err.Error())
	if strings.HasPrefix(msg, "usage:") {
		return apstoreExitUsage
	}
	return apstoreExitFailure
}

func exitCodeForResultCode(code string) int {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "":
		return apstoreExitFailure
	case apstoreCodeIPCUnavailable:
		return apstoreExitUnavailable
	case protocol.ErrCodeAuthenticationFailed,
		protocol.ErrCodeInvalidPassphrase,
		protocol.ErrCodeUnlockFailed,
		protocol.ErrCodeAuthorizationDenied,
		protocol.ErrCodeSignerLocked,
		protocol.ErrCodeNoRuntimeBound:
		return apstoreExitUnavailable
	case protocol.ResultCodeRestoreRateLimited:
		return apstoreExitRateLimited
	case protocol.ResultCodeKeyTypeInUse,
		protocol.ResultCodeActivationFailed,
		protocol.ResultCodeDeactivationFailed,
		protocol.ResultCodeRemoveFailed,
		protocol.ResultCodeRestoreConflict,
		protocol.ResultCodeRestoreRollbackDiverged:
		return apstoreExitConflict
	case "verification_failed",
		"invalid_backup",
		"corrupt_archive",
		"bad_export_passphrase",
		"unsupported_backup_format":
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
