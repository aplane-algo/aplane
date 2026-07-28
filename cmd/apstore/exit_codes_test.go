// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestExitCodeForResultCode(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		// Conflict-class refusals exit with the conventional conflict code
		// so scripts can distinguish "retry after resolving" from failure.
		{protocol.ResultCodeActivationConflict, apstoreExitConflict},
		{protocol.ResultCodeActivationReviewStale, apstoreExitConflict},
		{protocol.ResultCodeActivationAckRequired, apstoreExitConflict},
		{protocol.ResultCodeRecoveredRollbackDiverged, apstoreExitConflict},
		{protocol.ResultCodeKeyTypeInUse, apstoreExitConflict},
		{protocol.ResultCodeActivationFailed, apstoreExitConflict},
		{protocol.ResultCodeDeactivationFailed, apstoreExitConflict},
		{protocol.ResultCodeRemoveFailed, apstoreExitConflict},
		{protocol.ResultCodeRestoreRateLimited, apstoreExitRateLimited},
		{apstoreCodeIPCUnavailable, apstoreExitUnavailable},
		{protocol.ErrCodeSignerLocked, apstoreExitUnavailable},
		{protocol.ErrCodeInvalidRequest, apstoreExitUsage},
		{"corrupt_archive", apstoreExitArchive},
		{"", apstoreExitFailure},
		{protocol.ResultCodeRecoveryBlocked, apstoreExitFailure},
		{"unknown_future_code", apstoreExitFailure},
	}
	for _, tc := range cases {
		if got := exitCodeForResultCode(tc.code); got != tc.want {
			t.Errorf("exitCodeForResultCode(%q) = %d, want %d", tc.code, got, tc.want)
		}
	}
}
