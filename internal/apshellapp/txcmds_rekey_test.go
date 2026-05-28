// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "testing"

func TestDecorateRekeyResultForSignableLsigTarget(t *testing.T) {
	result := &RekeyCommandResult{
		From:             "FROM",
		To:               "TO",
		CanSignForTarget: true,
		TargetIsLsig:     true,
	}

	decorateRekeyResult(result)

	if len(result.PreSubmitLines) == 0 {
		t.Fatal("PreSubmitLines empty")
	}
	if got, want := result.ConfirmedLines[0], "Account {from} is now rekeyed to lsig {to}"; got != want {
		t.Fatalf("ConfirmedLines[0] = %q, want %q", got, want)
	}
}

func TestDecorateRekeyResultForExternalTarget(t *testing.T) {
	result := &RekeyCommandResult{
		From:             "FROM",
		To:               "TO",
		CanSignForTarget: false,
	}

	decorateRekeyResult(result)

	if len(result.PreSubmitLines) == 0 {
		t.Fatal("PreSubmitLines empty")
	}
	if got, want := result.PreSubmitLines[1], "Target address: {to}"; got != want {
		t.Fatalf("PreSubmitLines[1] = %q, want %q", got, want)
	}
	if got, want := result.PendingLines[0], "Target is an address you cannot sign for - you'll need the new auth address's private key to sign."; got != want {
		t.Fatalf("PendingLines[0] = %q, want %q", got, want)
	}
}

func TestDecorateRekeyResultForUnrekey(t *testing.T) {
	result := &RekeyCommandResult{
		From:               "FROM",
		CurrentAuthAddress: "AUTH",
		IsUnrekey:          true,
	}

	decorateRekeyResult(result)

	if got, want := result.PreSubmitLines[0], "Account is currently rekeyed to: {current_auth}"; got != want {
		t.Fatalf("PreSubmitLines[0] = %q, want %q", got, want)
	}
	if got, want := result.ConfirmedLines[0], "Account {from} is now back to normal (no rekey in effect)"; got != want {
		t.Fatalf("ConfirmedLines[0] = %q, want %q", got, want)
	}
}
