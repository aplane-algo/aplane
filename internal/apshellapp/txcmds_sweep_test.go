// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// An ASA sweep sends all above what is to be left, whatever the fee: its fee
// is paid in ALGO, not the swept asset. Nothing is built or reserved, so it
// cannot fail on an unrelated algod or profile error: the App here has no
// engine, and touching it would panic.
func TestSettleSweepAmountsForAnASABuildsNothing(t *testing.T) {
	app := &App{}
	got, err := app.settleSweepAmounts(context.Background(), 10458941, "A", "B", 10_000, 1_000, 2_000, true)
	if err != nil || !got.ok || got.send != 9_000 || got.feeReserve != 0 {
		t.Fatalf("settleSweepAmounts(ASA) = %+v, %v; want 9000 sent and nothing reserved", got, err)
	}
	if got, _ := app.settleSweepAmounts(context.Background(), 10458941, "A", "B", 1_000, 1_000, 0, false); got.ok {
		t.Fatalf("settleSweepAmounts(ASA, nothing above leaving) = %+v, want nothing to send", got)
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
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 1_000, 0)
	if !ok {
		t.Fatal("sweepSendAmount() ok = false, want true")
	}
	if amount != 8_000 || feeReserve != 1_000 {
		t.Fatalf("sweepSendAmount() = (%d, %d), want amount 8000 fee 1000", amount, feeReserve)
	}

	// A fee above the minimum, suggested per byte or given flat, is reserved
	// as it is.
	amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 2_000, 0)
	if !ok {
		t.Fatal("sweepSendAmount(fee above minimum) ok = false, want true")
	}
	if amount != 7_000 || feeReserve != 2_000 {
		t.Fatalf("sweepSendAmount(fee above minimum) = (%d, %d), want amount 7000 fee 2000", amount, feeReserve)
	}

	if _, feeReserve, ok = sweepSendAmount(2_000, 1_000, 1_000, 0); ok || feeReserve != 1_000 {
		t.Fatalf("sweepSendAmount(insufficient) ok=%v fee=%d, want false/1000", ok, feeReserve)
	}

	// An explicit flat zero fee is authoritative: sweepPaymentFee passes it
	// through, and nothing is reserved for it.
	amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 0, 0)
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
	amount, feeReserve, ok := sweepSendAmount(10_000, 1_000, 1_000, 3_000)
	if !ok {
		t.Fatal("sweepSendAmount(dummy reserve) ok = false, want true")
	}
	if amount != 5_000 || feeReserve != 4_000 {
		t.Fatalf("sweepSendAmount(dummy reserve) = (%d, %d), want amount 5000 fee 4000", amount, feeReserve)
	}

	// Dummy reserve applies on top of a higher fee too.
	if amount, feeReserve, ok = sweepSendAmount(10_000, 1_000, 2_000, 3_000); !ok || amount != 4_000 || feeReserve != 5_000 {
		t.Fatalf("sweepSendAmount(fee+dummy) = (%d, %d, %v), want 4000/5000/true", amount, feeReserve, ok)
	}
}

// wantFailedAtSigning checks that a one-source sweep failed where the fixture
// makes it fail: at signing, after its payment was prepared, because the test
// signer answers 503. Any other outcome is a breakage the test must not pass.
func wantFailedAtSigning(t *testing.T, result *SweepCommandResult, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "all 1 transaction(s) failed") || result == nil ||
		len(result.Items) != 1 || !strings.HasPrefix(result.Items[0].Error, "transaction failed: ") {
		t.Fatalf("Sweep() = %+v, %v; want it to fail at signing, after preparing", result, err)
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
			result, err := f.app.Sweep(context.Background(), SweepRequest{
				AssetRef: "algo", FromRaw: []string{tc.from}, ToRaw: "dest", LeavingRaw: &left,
				Fee: tc.fee, UseFlatFee: tc.useFlatFee, Wait: true,
			})
			wantFailedAtSigning(t, result, err)
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
//     be prepared (the signer holds no key for dest) is still only skipped,
//     and told the fee it was compared against, not a reserve.
func TestSweepSkipsAnAccountWithNothingToSend(t *testing.T) {
	const balance, perByte, charge = 5_000_000, 25, 2_000
	f0 := newArgsFixture(t)
	shortReserve := f0.suggestedFee(t, argsFalcon, 5_000, perByte) + charge
	for _, tc := range []struct {
		name       string
		from, to   string
		leaving    uint64
		perByte    uint64
		fee        uint64
		useFlatFee bool
		want       string // after "... after the leaving amount <leaving> and "
	}{
		{"short of the reserve", argsFalcon, "dest", balance - 5_000, perByte, 0, false, fmt.Sprintf("fee reserve %d", shortReserve)},
		{"exactly the reserve", argsFalcon, "dest", balance - 1_000 - charge, 0, 0, false, fmt.Sprintf("fee reserve %d", 1_000+charge)},
		{"below the minimum fee, cannot be prepared", argsDest, "nat", balance - 500, 0, 0, false, "a fee of at least 1000"},
		{"below a flat fee, cannot be prepared", argsDest, "nat", balance - 2_500, 0, 3_000, true, "a fee of at least 3000"},
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
			want := fmt.Sprintf("balance %d leaves nothing to send after the leaving amount %d and %s", balance, tc.leaving, tc.want)
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

// A rotating account is reserved for as itself at any stage. Its auth
// address, cached by the sweep's build, is a stage the signer never lists; the
// build signs as the account itself, so the reserve is the account's own
// profile's, not 0. Its payment, once prepared, goes to the rotating flow,
// which first reads the current round from the test node; the node answers
// 503 there, so that is where the sweep is expected to fail, and nothing
// reaches the signer. The amount is checked on the item.
func TestSweepReservesForARotatingAccountAtAnyStage(t *testing.T) {
	const balance, leaving, perByte = 5_000_000, 4_930_000, 25
	f := newArgsFixture(t)
	f.perByteFee.Store(perByte)
	reserve, err := f.eng.AuthorizationFeeReserve(argsRotating)
	if err != nil || reserve == 0 {
		t.Fatalf("AuthorizationFeeReserve() = %d, %v; want the profile's reserve", reserve, err)
	}
	left := uint64(leaving)
	result, err := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{argsRotating}, ToRaw: "dest", LeavingRaw: &left, Wait: true,
	})
	wantFailedAtSigning(t, result, err)
	if !strings.Contains(result.Items[0].Error, "read current round: HTTP 503: test node") {
		t.Fatalf("item error = %q, want the rotating flow to fail reading the round", result.Items[0].Error)
	}
	if auth, _ := f.eng.GetAuthAddress(argsRotating); auth != argsStage {
		t.Fatalf("cached auth address = %q, want the stage %s", auth, argsStage)
	}
	fee := f.suggestedFee(t, argsRotating, balance-leaving, perByte)
	if got := result.Items[0].Amount.Raw + fee + reserve; got != balance-leaving {
		t.Fatalf("amount %d + fee %d + reserve %d = %d, want %d", result.Items[0].Amount.Raw, fee, reserve, got, balance-leaving)
	}
}

// The reserve is for the address the sweep's build signs with, whether or not
// the build could write the auth cache. Here the client data directory cannot
// be created, so that write fails and is only logged: an ed25519 account
// rekeyed to native Falcon must still reserve the 2,000 Falcon charge. Signing
// then fails, as expected, when it cannot refresh the auth address under the
// same lock; the amount is checked on the item.
func TestSweepReservesForTheSigningKeyWithoutTheAuthCache(t *testing.T) {
	const balance, leaving, perByte, charge = 5_000_000, 4_930_000, 25, 2_000
	f := newArgsFixture(t)
	f.perByteFee.Store(perByte)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.eng.DataDir = filepath.Join(blocker, "data")
	left := uint64(leaving)
	result, err := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{argsRekeyed}, ToRaw: "dest", LeavingRaw: &left, Wait: true,
	})
	wantFailedAtSigning(t, result, err)
	if !strings.Contains(result.Items[0].Error, "failed to refresh auth address") {
		t.Fatalf("item error = %q, want signing to fail refreshing the auth address", result.Items[0].Error)
	}
	if _, cached := f.eng.GetAuthAddress(argsRekeyed); cached {
		t.Fatal("the auth cache was written: the case tests nothing")
	}
	fee := f.suggestedFee(t, argsRekeyed, balance-leaving, perByte)
	if got := result.Items[0].Amount.Raw + fee + charge; got != balance-leaving {
		t.Fatalf("amount %d + fee %d + charge %d = %d, want %d", result.Items[0].Amount.Raw, fee, charge, got, balance-leaving)
	}
}
