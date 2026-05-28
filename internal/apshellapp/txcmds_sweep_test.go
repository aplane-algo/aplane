// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
)

func TestDecorateSweepResult(t *testing.T) {
	result := &SweepCommandResult{
		Asset: asa.Metadata{
			AssetID:  0,
			UnitName: "ALGO",
		},
		Leaving: asa.AmountFromRaw(1000000, asa.Metadata{
			AssetID:  0,
			UnitName: "ALGO",
		}),
		FromAddresses:   []string{"A", "B"},
		ToAddress:       "C",
		UsedAllSignable: true,
		ReceiverOptedIn: true,
		SuccessCount:    2,
		FailureCount:    1,
		LastTxID:        "TXID",
	}

	decorateSweepResult(result)

	if got, want := result.InfoLines[0], "No source accounts specified, using all signable accounts..."; got != want {
		t.Fatalf("InfoLines[0] = %q, want %q", got, want)
	}
	if got, want := result.HeaderLine, "Sweeping ALGO from 2 account(s) to {to} (leaving 1000000 ALGO in each)"; got != want {
		t.Fatalf("HeaderLine = %q, want %q", got, want)
	}
	if got, want := result.SummaryLines[0], "Sweep complete: 2 succeeded, 1 failed"; got != want {
		t.Fatalf("SummaryLines[0] = %q, want %q", got, want)
	}
}

func TestSweepSendAmountReservesAlgoFee(t *testing.T) {
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 0, 0, false)
	if !ok {
		t.Fatal("sweepSendAmount() ok = false, want true")
	}
	if amount != 8_000 || feeReserve != 1_000 {
		t.Fatalf("sweepSendAmount() = (%d, %d), want amount 8000 fee 1000", amount, feeReserve)
	}

	amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 0, 2_000, true)
	if !ok {
		t.Fatal("sweepSendAmount(flat fee) ok = false, want true")
	}
	if amount != 7_000 || feeReserve != 2_000 {
		t.Fatalf("sweepSendAmount(flat fee) = (%d, %d), want amount 7000 fee 2000", amount, feeReserve)
	}

	if _, feeReserve, ok = sweepSendAmount(2_000, 1_000, 0, 0, false); ok || feeReserve != 1_000 {
		t.Fatalf("sweepSendAmount(insufficient) ok=%v fee=%d, want false/1000", ok, feeReserve)
	}
}

func TestSweepSendAmountDoesNotReserveASATransferFee(t *testing.T) {
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 10458941, 0, false)
	if !ok {
		t.Fatal("sweepSendAmount(ASA) ok = false, want true")
	}
	if amount != 9_000 || feeReserve != 0 {
		t.Fatalf("sweepSendAmount(ASA) = (%d, %d), want amount 9000 fee 0", amount, feeReserve)
	}
}
