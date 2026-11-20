// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const (
	apstoreExitOK          = 0
	apstoreExitFailure     = 1
	apstoreExitUsage       = 2
	apstoreExitUnavailable = 3
	apstoreExitArchive     = 6
)

// policyIntegrityFailedCode classifies policy document integrity failures,
// which exit apstoreExitFailure.
const policyIntegrityFailedCode = "policy_integrity_failed"

// usageError is a malformed command line: a missing, unknown, duplicate or
// invalid argument. It exits apstoreExitUsage, whatever its wording.
type usageError struct {
	message string
}

func (e usageError) Error() string { return e.message }

func usageErrorf(format string, args ...any) error {
	return usageError{message: fmt.Sprintf(format, args...)}
}

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
	var usage usageError
	if errors.As(err, &usage) {
		return apstoreExitUsage
	}
	var coded codedError
	if errors.As(err, &coded) {
		return exitCodeForResultCode(coded.code)
	}
	return apstoreExitFailure
}

// exitCodeForResultCode maps the codes apstore attaches to its errors.
func exitCodeForResultCode(code string) int {
	switch code {
	case protocol.ErrCodeInvalidPassphrase:
		return apstoreExitUnavailable
	case "verification_failed", "corrupt_archive":
		return apstoreExitArchive
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
