// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "testing"

func TestDecorateCloseResult(t *testing.T) {
	result := &CloseCommandResult{
		From:           "FROM",
		CloseTo:        "TO",
		Balance:        2500000,
		SigningKeyType: "ed25519",
	}

	decorateCloseResult(result)

	if len(result.PreSubmitLines) != 1 {
		t.Fatalf("len(PreSubmitLines) = %d, want 1", len(result.PreSubmitLines))
	}
	if got, want := result.PreSubmitLines[0], "Closing account {from} (2.500000 ALGO) to {to} using ed25519..."; got != want {
		t.Fatalf("PreSubmitLines[0] = %q, want %q", got, want)
	}
	if got, want := result.ConfirmedLines[0], "Account {from} closed to {to}"; got != want {
		t.Fatalf("ConfirmedLines[0] = %q, want %q", got, want)
	}
}
