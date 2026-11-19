// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestExitCodeForStructuredResultCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "rate limited",
			err:  resultError("restore failed", protocol.ResultCodeRestoreRateLimited, "too many restores"),
			want: apstoreExitRateLimited,
		},
		{
			name: "key type in use",
			err:  resultError("template import failed", protocol.ResultCodeKeyTypeInUse, "key(s) still use it"),
			want: apstoreExitConflict,
		},
		{
			name: "archive verification",
			err:  resultError("backup failed", "verification_failed", "checksum mismatch"),
			want: apstoreExitArchive,
		},
		{
			name: "auth failure",
			err:  codedError{code: protocol.ErrCodeAuthenticationFailed, message: "authentication failed"},
			want: apstoreExitUnavailable,
		},
		{
			name: "transport coded auth failure",
			err:  protocol.WithCode(protocol.ErrCodeAuthenticationFailed, fmt.Errorf("authentication failed: invalid passphrase")),
			want: apstoreExitUnavailable,
		},
		{
			name: "local ipc unavailable",
			err:  codedError{code: apstoreCodeIPCUnavailable, message: "failed to connect to IPC socket: missing"},
			want: apstoreExitUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeForError(tt.err); got != tt.want {
				t.Fatalf("exitCodeForError(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestExitCodeDoesNotClassifyResultCodesFromProse(t *testing.T) {
	err := fmt.Errorf("remote result included restore_rate_limited in message text but no code")
	if got := exitCodeForError(err); got != apstoreExitFailure {
		t.Fatalf("exitCodeForError(%v) = %d, want generic failure", err, got)
	}
}

func TestExitCodeDoesNotClassifyRemoteOutcomesFromProse(t *testing.T) {
	tests := []error{
		fmt.Errorf("authentication failed: invalid passphrase"),
		fmt.Errorf("authorization denied"),
		fmt.Errorf("signer is locked"),
		fmt.Errorf("provider collision"),
		fmt.Errorf("key(s) still use it"),
		fmt.Errorf("checksum mismatch"),
	}

	for _, err := range tests {
		if got := exitCodeForError(err); got != apstoreExitFailure {
			t.Fatalf("exitCodeForError(%v) = %d, want generic failure", err, got)
		}
	}
}

// Every malformed command line exits with the usage code, whatever its
// message says, and a failure that merely starts with "usage:" does not.
func TestExitCodeForLocalUsageError(t *testing.T) {
	_, initializeErr := parseInitializeRole([]string{"--role", "bogus"})
	_, pruneErr := parsePruneArgs([]string{"--yes", "--yes"})
	_, uidErr := func() (int, error) {
		uid, _, err := parseManagedPrincipalFlags("permissions convert-managed", []string{"--uid", "x", "--gid", "1"})
		return uid, err
	}()
	_, verifyErr := verifyBackupPathFromArgs([]string{"verify", "backup.tar.gz", "--deep"})
	usageErrors := map[string]error{
		"keys":                 cmdKeys([]string{"show"}),
		"policy":               cmdPolicy([]string{"bogus"}),
		"rebuild option":       cmdRebuild([]string{"archive.tar.gz", "--bogus"}),
		"rebuild role":         cmdRebuild([]string{"archive.tar.gz", "--role", "bogus"}),
		"generations":          cmdGenerations([]string{"bogus"}),
		"duplicate prune flag": pruneErr,
		"initialize role":      initializeErr,
		"managed service uid":  uidErr,
		"verify option":        verifyErr,
	}
	for name, err := range usageErrors {
		if err == nil {
			t.Fatalf("%s: no error for a malformed command line", name)
		}
		if got := exitCodeForError(err); got != apstoreExitUsage {
			t.Fatalf("%s: exitCodeForError(%v) = %d, want %d", name, err, got, apstoreExitUsage)
		}
	}
	if got := exitCodeForError(fmt.Errorf("usage: of the store failed")); got != apstoreExitFailure {
		t.Fatalf("exitCodeForError(prose) = %d, want %d", got, apstoreExitFailure)
	}
}

func TestVerifyBackupPathFromArgsRejectsDeepOption(t *testing.T) {
	if _, err := verifyBackupPathFromArgs([]string{"verify", "backup.tar.gz", "--deep"}); err == nil {
		t.Fatal("verifyBackupPathFromArgs(--deep) error = nil, want unknown option")
	} else if !strings.Contains(err.Error(), "unknown verify option: --deep") {
		t.Fatalf("verifyBackupPathFromArgs(--deep) error = %v, want unknown option", err)
	}
}

func TestConfirmYesNoDefaultsToSafeCancellation(t *testing.T) {
	for _, input := range []string{"\n", "n\n", "no\n", "anything else\n"} {
		input := input
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			err := withTestStdin(input, func() error {
				if confirmYesNo("") {
					t.Fatalf("confirmYesNo(%q) = true, want false", input)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("withTestStdin() error = %v", err)
			}
		})
	}
}
