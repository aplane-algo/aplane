// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

func TestAuthorizationFeeReserveForSweepSkipsASA(t *testing.T) {
	called := false
	reserve := func(string) (uint64, error) {
		called = true
		return 0, errors.New("authorization reserve should not be queried")
	}

	got, err := authorizationFeeReserveForSweep(10458941, "ADDR", reserve)
	if err != nil || got != 0 {
		t.Fatalf("authorizationFeeReserveForSweep(ASA) = %d, %v; want 0, nil", got, err)
	}
	if called {
		t.Fatal("authorization reserve dependency was called for an ASA sweep")
	}
}

func TestAuthorizationFeeReserveForSweepUsesAlgoReserve(t *testing.T) {
	reserve := func(sender string) (uint64, error) {
		if sender != "ADDR" {
			t.Fatalf("reserve sender = %q, want ADDR", sender)
		}
		return 2_000, nil
	}

	got, err := authorizationFeeReserveForSweep(0, "ADDR", reserve)
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
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 0, 1_000, 0)
	if !ok {
		t.Fatal("sweepSendAmount() ok = false, want true")
	}
	if amount != 8_000 || feeReserve != 1_000 {
		t.Fatalf("sweepSendAmount() = (%d, %d), want amount 8000 fee 1000", amount, feeReserve)
	}

	// A fee above the minimum, suggested per byte or given flat, is reserved
	// as it is.
	amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 0, 2_000, 0)
	if !ok {
		t.Fatal("sweepSendAmount(fee above minimum) ok = false, want true")
	}
	if amount != 7_000 || feeReserve != 2_000 {
		t.Fatalf("sweepSendAmount(fee above minimum) = (%d, %d), want amount 7000 fee 2000", amount, feeReserve)
	}

	if _, feeReserve, ok = sweepSendAmount(2_000, 1_000, 0, 1_000, 0); ok || feeReserve != 1_000 {
		t.Fatalf("sweepSendAmount(insufficient) ok=%v fee=%d, want false/1000", ok, feeReserve)
	}

	// An explicit flat zero fee is authoritative: sweepPaymentFee passes it
	// through, and nothing is reserved for it.
	amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 0, 0, 0)
	if !ok {
		t.Fatal("sweepSendAmount(flat zero) ok = false, want true")
	}
	if amount != 9_000 || feeReserve != 0 {
		t.Fatalf("sweepSendAmount(flat zero) = (%d, %d), want amount 9000 fee 0", amount, feeReserve)
	}
}

// TestSweepSendAmountReservesDummyFees pins finding 2B: an ALGO sweep from a
// LogicSig account reserves the payment's fee plus the dummy-transaction fees
// the signer pools onto it, so it cannot overspend and fail.
func TestSweepSendAmountReservesDummyFees(t *testing.T) {
	// fee 1000 + 3000 dummy reserve = 4000 reserved.
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 0, 1_000, 3_000)
	if !ok {
		t.Fatal("sweepSendAmount(dummy reserve) ok = false, want true")
	}
	if amount != 5_000 || feeReserve != 4_000 {
		t.Fatalf("sweepSendAmount(dummy reserve) = (%d, %d), want amount 5000 fee 4000", amount, feeReserve)
	}

	// Dummy reserve applies on top of a higher fee too.
	if amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 0, 2_000, 3_000); !ok || amount != 4_000 || feeReserve != 5_000 {
		t.Fatalf("sweepSendAmount(fee+dummy) = (%d, %d, %v), want 4000/5000/true", amount, feeReserve, ok)
	}

	// ASA sweeps pay fees from the ALGO balance, not the asset, so the dummy
	// reserve does not reduce the swept asset amount.
	if amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 10458941, 0, 3_000); !ok || amount != 9_000 || feeReserve != 0 {
		t.Fatalf("sweepSendAmount(ASA+dummy) = (%d, %d, %v), want 9000/0/true", amount, feeReserve, ok)
	}
}

func TestSweepSendAmountDoesNotReserveASATransferFee(t *testing.T) {
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 10458941, 1_000, 0)
	if !ok {
		t.Fatal("sweepSendAmount(ASA) ok = false, want true")
	}
	if amount != 9_000 || feeReserve != 0 {
		t.Fatalf("sweepSendAmount(ASA) = (%d, %d), want amount 9000 fee 0", amount, feeReserve)
	}
}

// sweptPayment is the one payment a sweep sent the test signer.
func (f *argsFixture) sweptPayment(t *testing.T) types.Transaction {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.signs) != 1 || len(f.signs[0]) != 1 {
		t.Fatalf("/sign requests = %+v, want one with one transaction", f.signs)
	}
	txn, err := txnutil.DecodePrefixedHex(f.signs[0][0].TxnBytesHex)
	if err != nil {
		t.Fatalf("decode the swept payment: %v", err)
	}
	return txn
}

// suggestedFee is the fee the SDK gives a payment of amount from from to
// argsDest on the fixture's network at perByte microAlgos a byte.
func (f *argsFixture) suggestedFee(t *testing.T, from string, amount, perByte uint64) uint64 {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(from, argsDest, amount, nil, "", types.SuggestedParams{
		Fee: types.MicroAlgos(perByte), FirstRoundValid: 1000, LastRoundValid: 2000, GenesisHash: f.genesis, GenesisID: "testnet-v1.0",
	})
	if err != nil {
		t.Fatalf("make txn: %v", err)
	}
	return uint64(txn.Fee)
}

// An ALGO sweep leaves the account exactly what is to be left, whatever fee
// algod suggests: the payment pays the fee the largest amount the sweep could
// send is given, and the amount is what remains after that fee and the
// authorization charge the signer adds on top. The fixture's accounts hold
// 5,000,000, so leaving 4,930,000 makes the largest amount, 70,000, encode two
// bytes longer than the amount sent.
//
// The fixture's signer answers 503 and never applies a charge: charge is the
// one the signer would add, given here (2,000 for native Falcon: one PQ fee
// contribution at the 1,000 minimum fee). So these cases pin the client's
// arithmetic and which key it reserves for, not the signer's charge. A rekeyed
// account's auth address is not cached when the sweep starts, so the reserve
// must be for the key it is rekeyed to.
func TestSweepLeavesExactlyTheLeavingAmount(t *testing.T) {
	const balance, leaving, perByte = 5_000_000, 4_930_000, 25
	for _, tc := range []struct {
		name       string
		from       string
		perByte    uint64
		fee        uint64
		useFlatFee bool
		charge     uint64
	}{
		{"the minimum fee", argsNative, 0, 0, false, 0},
		{"a per-byte fee above the minimum", argsNative, perByte, 0, false, 0},
		{"a flat fee", argsNative, perByte, 3_000, true, 0},
		{"a flat zero", argsNative, perByte, 0, true, 0},
		{"native Falcon", argsFalcon, perByte, 0, false, 2_000},
		{"rekeyed to native Falcon", argsRekeyed, perByte, 0, false, 2_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgsFixture(t)
			f.perByteFee.Store(tc.perByte)
			if _, cached := f.eng.GetAuthAddress(tc.from); cached {
				t.Fatalf("auth address of %s is cached before the sweep", tc.from)
			}
			left := uint64(leaving)
			result, _ := f.app.Sweep(context.Background(), SweepRequest{
				AssetRef: "algo", FromRaw: []string{tc.from}, ToRaw: "dest", LeavingRaw: &left,
				Fee: tc.fee, UseFlatFee: tc.useFlatFee, Wait: true,
			})
			if result == nil || len(result.Items) != 1 || result.Items[0].SkippedReason != "" {
				t.Fatalf("Sweep() result = %+v", result)
			}
			txn := f.sweptPayment(t)
			wantFee := tc.fee
			if !tc.useFlatFee {
				wantFee = f.suggestedFee(t, tc.from, balance-leaving, tc.perByte)
			}
			if uint64(txn.Fee) != wantFee {
				t.Fatalf("fee = %d, want %d", txn.Fee, wantFee)
			}
			if got := uint64(txn.Amount) + uint64(txn.Fee) + tc.charge; got != balance-leaving {
				t.Fatalf("amount %d + fee %d + authorization charge %d = %d, want %d", txn.Amount, txn.Fee, tc.charge, got, balance-leaving)
			}
			if got := result.Items[0].Amount.Raw; got != uint64(txn.Amount) {
				t.Fatalf("item amount = %d, payment amount = %d", got, txn.Amount)
			}
			if tc.perByte > 0 && !tc.useFlatFee {
				if wantFee <= 1_000 {
					t.Fatalf("suggested fee %d is not above the minimum: the case tests nothing", wantFee)
				}
				if sent := f.suggestedFee(t, tc.from, uint64(txn.Amount), tc.perByte); sent >= wantFee {
					t.Fatalf("the amount sent is suggested %d, not less than %d: the case tests nothing", sent, wantFee)
				}
			}
		})
	}
}

// An account with nothing left to send after what is to be left and the fee
// reserve is skipped, not failed, and told the reserve. Nothing is sent. The
// fixture's accounts hold 5,000,000.
//   - Short of the reserve: at 25 microAlgos a byte the payment's fee and the
//     2,000 Falcon charge exceed the 5,000 above what is to be left. With the
//     minimum fee assumed, it would have sent 2,000 and been left below it.
//   - Exactly the reserve: the minimum fee and the Falcon charge leave nothing.
//   - Below the smallest fee the payment could carry (the minimum, or a flat
//     fee given): skipped before anything is built, so a source that cannot
//     be prepared (the signer holds no key for dest) is still only skipped.
func TestSweepSkipsAnAccountWithNothingToSend(t *testing.T) {
	const balance, perByte, charge = 5_000_000, 25, 2_000
	f0 := newArgsFixture(t)
	shortReserve := f0.suggestedFee(t, argsFalcon, 5_000, perByte) + charge
	for _, tc := range []struct {
		name        string
		from, to    string
		leaving     uint64
		perByte     uint64
		fee         uint64
		useFlatFee  bool
		wantReserve uint64
	}{
		{"short of the reserve", argsFalcon, "dest", balance - 5_000, perByte, 0, false, shortReserve},
		{"exactly the reserve", argsFalcon, "dest", balance - 1_000 - charge, 0, 0, false, 1_000 + charge},
		{"below the minimum fee, cannot be prepared", argsDest, "nat", balance - 500, 0, 0, false, 1_000},
		{"below a flat fee, cannot be prepared", argsDest, "nat", balance - 2_500, 0, 3_000, true, 3_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgsFixture(t)
			f.perByteFee.Store(tc.perByte)
			left := tc.leaving
			result, err := f.app.Sweep(context.Background(), SweepRequest{
				AssetRef: "algo", FromRaw: []string{tc.from}, ToRaw: tc.to, LeavingRaw: &left,
				Fee: tc.fee, UseFlatFee: tc.useFlatFee, Wait: true,
			})
			if err != nil {
				t.Fatalf("Sweep() error = %v (items %+v)", err, result.Items)
			}
			want := fmt.Sprintf("balance %d leaves nothing to send after the leaving amount %d and fee reserve %d", balance, tc.leaving, tc.wantReserve)
			if len(result.Items) != 1 || result.Items[0].SkippedReason != want || result.FailureCount != 0 {
				t.Fatalf("sweep items = %+v, failures %d; want skipped: %s", result.Items, result.FailureCount, want)
			}
			if got := f.signerPosts.Load(); got != 0 {
				t.Fatalf("signer requests = %d, want none", got)
			}
		})
	}

	// The source above cannot be prepared: with more to send it fails.
	f := newArgsFixture(t)
	left := uint64(balance - 50_000)
	result, err := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{argsDest}, ToRaw: "nat", LeavingRaw: &left, Wait: true,
	})
	if err == nil || result == nil || len(result.Items) != 1 ||
		!strings.HasPrefix(result.Items[0].Error, "failed to prepare transaction: ") {
		t.Fatalf("Sweep() = %+v, %v; want the source to fail to be prepared", result, err)
	}
}

// A rotating account is reserved for as itself at any stage. The sweep's
// first build caches its auth address, a stage the signer never lists, and
// the reserve must still be the account's own profile's, not 0. The reserve
// read before the sweep, with nothing cached, is that profile's. Its payment
// goes through the rotating flow, which the test signer does not record, so
// the amount is checked on the item.
func TestSweepReservesForARotatingAccountAtAnyStage(t *testing.T) {
	const balance, leaving, perByte = 5_000_000, 4_930_000, 25
	f := newArgsFixture(t)
	f.perByteFee.Store(perByte)
	reserve, err := f.eng.AuthorizationFeeReserve(argsRotating)
	if err != nil || reserve == 0 {
		t.Fatalf("AuthorizationFeeReserve() = %d, %v; want the profile's reserve", reserve, err)
	}
	left := uint64(leaving)
	result, _ := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{argsRotating}, ToRaw: "dest", LeavingRaw: &left, Wait: true,
	})
	if result == nil || len(result.Items) != 1 || result.Items[0].SkippedReason != "" || result.Items[0].Amount.Raw == 0 {
		t.Fatalf("Sweep() result = %+v", result)
	}
	if auth, _ := f.eng.GetAuthAddress(argsRotating); auth != argsStage {
		t.Fatalf("cached auth address = %q, want the stage %s", auth, argsStage)
	}
	fee := f.suggestedFee(t, argsRotating, balance-leaving, perByte)
	if got := result.Items[0].Amount.Raw + fee + reserve; got != balance-leaving {
		t.Fatalf("amount %d + fee %d + reserve %d = %d, want %d", result.Items[0].Amount.Raw, fee, reserve, got, balance-leaving)
	}
}
