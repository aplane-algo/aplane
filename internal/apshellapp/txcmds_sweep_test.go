// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
)

func TestAuthorizationFeeReserveForSweepSkipsASA(t *testing.T) {
	called := false
	reserve := func(context.Context, string) (uint64, error) {
		called = true
		return 0, errors.New("authorization reserve should not be queried")
	}

	got, err := authorizationFeeReserveForSweep(t.Context(), 10458941, "ADDR", reserve)
	if err != nil || got != 0 {
		t.Fatalf("authorizationFeeReserveForSweep(ASA) = %d, %v; want 0, nil", got, err)
	}
	if called {
		t.Fatal("authorization reserve dependency was called for an ASA sweep")
	}
}

func TestAuthorizationFeeReserveForSweepUsesAlgoReserve(t *testing.T) {
	reserve := func(_ context.Context, sender string) (uint64, error) {
		if sender != "ADDR" {
			t.Fatalf("reserve sender = %q, want ADDR", sender)
		}
		return 2_000, nil
	}

	got, err := authorizationFeeReserveForSweep(t.Context(), 0, "ADDR", reserve)
	if err != nil || got != 2_000 {
		t.Fatalf("authorizationFeeReserveForSweep(ALGO) = %d, %v; want 2000, nil", got, err)
	}
}

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
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 0, 0, false, 0)
	if !ok {
		t.Fatal("sweepSendAmount() ok = false, want true")
	}
	if amount != 8_000 || feeReserve != 1_000 {
		t.Fatalf("sweepSendAmount() = (%d, %d), want amount 8000 fee 1000", amount, feeReserve)
	}

	amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 0, 2_000, true, 0)
	if !ok {
		t.Fatal("sweepSendAmount(flat fee) ok = false, want true")
	}
	if amount != 7_000 || feeReserve != 2_000 {
		t.Fatalf("sweepSendAmount(flat fee) = (%d, %d), want amount 7000 fee 2000", amount, feeReserve)
	}

	if _, feeReserve, ok = sweepSendAmount(2_000, 1_000, 0, 0, false, 0); ok || feeReserve != 1_000 {
		t.Fatalf("sweepSendAmount(insufficient) ok=%v fee=%d, want false/1000", ok, feeReserve)
	}

	// An explicit flat zero fee is authoritative when opted in (useFlatFee=true,
	// fee=0): the reserve is a flat zero, not the default min fee. This matches
	// the unified fee model rather than the old `useFlatFee && fee > 0` guard
	// that silently substituted the default for a flat zero.
	amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 0, 0, true, 0)
	if !ok {
		t.Fatal("sweepSendAmount(flat zero) ok = false, want true")
	}
	if amount != 9_000 || feeReserve != 0 {
		t.Fatalf("sweepSendAmount(flat zero) = (%d, %d), want amount 9000 fee 0", amount, feeReserve)
	}
}

// TestSweepSendAmountReservesDummyFees pins finding 2B: an ALGO sweep from a
// LogicSig account reserves the base fee plus the dummy-transaction fees the
// signer pools onto it, so it cannot overspend and fail.
func TestSweepSendAmountReservesDummyFees(t *testing.T) {
	// base 1000 + 3000 dummy reserve = 4000 reserved.
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 0, 0, false, 3_000)
	if !ok {
		t.Fatal("sweepSendAmount(dummy reserve) ok = false, want true")
	}
	if amount != 5_000 || feeReserve != 4_000 {
		t.Fatalf("sweepSendAmount(dummy reserve) = (%d, %d), want amount 5000 fee 4000", amount, feeReserve)
	}

	// Dummy reserve applies on top of a flat base fee too.
	if amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 0, 2_000, true, 3_000); !ok || amount != 4_000 || feeReserve != 5_000 {
		t.Fatalf("sweepSendAmount(flat+dummy) = (%d, %d, %v), want 4000/5000/true", amount, feeReserve, ok)
	}

	// ASA sweeps pay fees from the ALGO balance, not the asset, so the dummy
	// reserve does not reduce the swept asset amount.
	if amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 10458941, 0, false, 3_000); !ok || amount != 9_000 || feeReserve != 0 {
		t.Fatalf("sweepSendAmount(ASA+dummy) = (%d, %d, %v), want 9000/0/true", amount, feeReserve, ok)
	}
}

func TestSweepSendAmountDoesNotReserveASATransferFee(t *testing.T) {
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 10458941, 0, false, 0)
	if !ok {
		t.Fatal("sweepSendAmount(ASA) ok = false, want true")
	}
	if amount != 9_000 || feeReserve != 0 {
		t.Fatalf("sweepSendAmount(ASA) = (%d, %d), want amount 9000 fee 0", amount, feeReserve)
	}
}
