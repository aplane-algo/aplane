// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestExitCodeForResultCode(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		{protocol.ErrCodeInvalidPassphrase, apstoreExitUnavailable},
		{"verification_failed", apstoreExitArchive},
		{"corrupt_archive", apstoreExitArchive},
		{policyIntegrityFailedCode, apstoreExitFailure},
		{"initialize_store_failed", apstoreExitFailure},
		{"", apstoreExitFailure},
		{"unknown_future_code", apstoreExitFailure},
	}
	for _, tc := range cases {
		if got := exitCodeForResultCode(tc.code); got != tc.want {
			t.Errorf("exitCodeForResultCode(%q) = %d, want %d", tc.code, got, tc.want)
		}
	}
}

// Every code apstore attaches to an error keeps its exit status.
func TestExitCodeForProducedCodes(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{codedError{code: protocol.ErrCodeInvalidPassphrase, message: "x"}, 3},
		{codedError{code: "verification_failed", message: "x"}, 6},
		{codedError{code: "corrupt_archive", message: "x"}, 6},
		{codedError{code: policyIntegrityFailedCode, message: "x"}, 1},
		{resultError("keystore initialization failed", "initialize_store_failed", "x"), 1},
		{codedError{message: "x"}, 1},
		{fmt.Errorf("wrapped: %w", codedError{code: "corrupt_archive", message: "x"}), 6},
		{usageErrorf("usage"), 2},
		{errors.New("plain"), 1},
		{nil, 0},
	}
	for _, tt := range tests {
		if got := exitCodeForError(tt.err); got != tt.want {
			t.Errorf("exitCodeForError(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}
