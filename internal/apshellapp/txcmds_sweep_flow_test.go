// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// The fixture's accounts hold 5,000,000 microAlgos.
const sweepFixtureBalance = 5_000_000

// sweepTestAsset is an asset the fixture's client knows: two decimals.
const sweepTestAsset = 77

func knowSweepTestAsset(f *argsFixture) {
	f.eng.AsaCache.Assets = map[uint64]cache.ASAInfo{sweepTestAsset: {Decimals: 2, Name: "Test Token", UnitName: "TST"}}
}

func holding(amount uint64) []models.AssetHolding {
	return []models.AssetHolding{{AssetId: sweepTestAsset, Amount: amount}}
}

// A sweep that cannot be set up fails before any source is looked at, and
// nothing reaches the signer.
func TestSweepRefusesBeforeAnySource(t *testing.T) {
	raw := func(n uint64) *uint64 { return &n }
	tests := []struct {
		name  string
		setup func(f *argsFixture)
		req   SweepRequest
		want  string // the error's prefix
	}{
		{name: "an unknown source", req: SweepRequest{AssetRef: "algo", FromRaw: []string{"nobody"}, ToRaw: "dest"},
			want: "failed to resolve source addresses: "},
		{name: "an unknown destination", req: SweepRequest{AssetRef: "algo", FromRaw: []string{"nat"}, ToRaw: "nobody"},
			want: "failed to resolve destination address: "},
		{name: "both kinds of LogicSig arguments",
			req: SweepRequest{AssetRef: "algo", FromRaw: []string{"hl"}, ToRaw: "dest",
				LsigArgs: words(t, "arg:preimage=aa"), UntargetedLsigArgs: map[string][]byte{"preimage": {1}}},
			want: "internal error: sweep was given LogicSig arguments both as arg: words and as untargeted arguments"},
		{name: "an unknown asset", req: SweepRequest{AssetRef: "nosuchcoin", FromRaw: []string{"nat"}, ToRaw: "dest"},
			want: `failed to resolve asset "nosuchcoin": `},
		{name: "a leaving amount that is not a number",
			req:  SweepRequest{AssetRef: "algo", FromRaw: []string{"nat"}, ToRaw: "dest", LeavingText: "lots"},
			want: "failed to convert leaving amount: "},
		{name: "a receiver not opted into the asset", setup: knowSweepTestAsset,
			req:  SweepRequest{AssetRef: "TST", FromRaw: []string{"nat"}, ToRaw: "dest", LeavingRaw: raw(0)},
			want: fmt.Sprintf("receiver %s is not opted into ASA %d (TST)", argsDest, sweepTestAsset)},
		{name: "a receiver the node cannot look up",
			setup: func(f *argsFixture) {
				knowSweepTestAsset(f)
				f.unreachable = argsDest
			},
			req:  SweepRequest{AssetRef: "TST", FromRaw: []string{"nat"}, ToRaw: "dest"},
			want: "failed to get receiver account info: "},

		// Two faults: the earlier step reports.
		{name: "sources before the destination", req: SweepRequest{AssetRef: "algo", FromRaw: []string{"nobody"}, ToRaw: "nobody"},
			want: "failed to resolve source addresses: "},
		{name: "LogicSig arguments before the asset",
			req: SweepRequest{AssetRef: "nosuchcoin", FromRaw: []string{"hl"}, ToRaw: "dest",
				LsigArgs: words(t, "arg:preimage=aa"), UntargetedLsigArgs: map[string][]byte{"preimage": {1}}},
			want: "internal error: sweep was given LogicSig arguments both"},
		{name: "the asset before the receiver",
			setup: func(f *argsFixture) { f.unreachable = argsDest },
			req:   SweepRequest{AssetRef: "nosuchcoin", FromRaw: []string{"nat"}, ToRaw: "dest"},
			want:  `failed to resolve asset "nosuchcoin": `},
		{name: "the receiver before the leaving amount", setup: knowSweepTestAsset,
			req:  SweepRequest{AssetRef: "TST", FromRaw: []string{"nat"}, ToRaw: "dest", LeavingText: "lots"},
			want: fmt.Sprintf("receiver %s is not opted into ASA %d (TST)", argsDest, sweepTestAsset)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newArgsFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			result, err := f.app.Sweep(context.Background(), tt.req)
			if result != nil || err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Fatalf("Sweep() = %+v, %v; want no result and an error starting %q", result, err, tt.want)
			}
			if got := f.signerPosts.Load(); got != 0 {
				t.Fatalf("signer requests = %d, want none", got)
			}
		})
	}
}

// sweepItemSummary is what a sweep recorded for one source, with the
// variable tail of an error cut off.
type sweepItemSummary struct {
	From, Skipped, ErrorPrefix string
	Amount                     uint64
}

func summarize(items []SweepItemResult, to string, t *testing.T) []sweepItemSummary {
	t.Helper()
	out := make([]sweepItemSummary, len(items))
	for i, item := range items {
		if item.To != to {
			t.Fatalf("item %d goes to %s, want %s", i, item.To, to)
		}
		prefix := item.Error
		if cut := strings.Index(prefix, ": "); cut >= 0 {
			prefix = prefix[:cut+2]
		}
		out[i] = sweepItemSummary{From: item.From, Skipped: item.SkippedReason, ErrorPrefix: prefix, Amount: item.Amount.Raw}
	}
	return out
}

// Each source gets one item, in the order asked for: skipped, failed before
// anything was built, or failed at the signer. Only failures count.
func TestSweepRecordsAnItemForEachSource(t *testing.T) {
	f := newArgsFixture(t)
	f.unfunded = argsHTLC
	f.unreachable = argsSecret
	leaving := uint64(4_000_000)
	result, err := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{"dest", "sec", "hl", "nat"}, ToRaw: "dest", LeavingRaw: &leaving, Wait: true,
	})
	if err == nil || err.Error() != "all 2 transaction(s) failed" {
		t.Fatalf("Sweep() error = %v, want all 2 transaction(s) failed", err)
	}
	want := []sweepItemSummary{
		{From: argsDest, Skipped: "source and destination are the same account"},
		{From: argsSecret, ErrorPrefix: "failed to get account info: "},
		{From: argsHTLC, Skipped: "balance 0 <= leaving amount 4000000"},
		{From: argsNative, ErrorPrefix: "transaction failed: ", Amount: sweepFixtureBalance - 4_000_000 - 1_000},
	}
	if got := summarize(result.Items, argsDest, t); !reflect.DeepEqual(got, want) {
		t.Fatalf("items = %+v\nwant    %+v", got, want)
	}
	if result.FailureCount != 2 || result.SuccessCount != 0 || result.LastTxID != "" {
		t.Fatalf("failures %d, successes %d, last txid %q; want 2, 0 and none", result.FailureCount, result.SuccessCount, result.LastTxID)
	}
	wantFrom := []string{argsDest, argsSecret, argsHTLC, argsNative}
	if !reflect.DeepEqual(result.FromAddresses, wantFrom) || result.ToAddress != argsDest || result.UsedAllSignable ||
		result.Leaving.Raw != leaving || result.LeavingMinimumBalance || result.ReceiverOptedIn {
		t.Fatalf("result header = %+v", result)
	}
	if got := f.signerPosts.Load(); got == 0 {
		t.Fatal("the one prepared payment never reached the signer")
	}
}

// A sweep whose sources were all skipped is not a failure.
func TestSweepWithOnlySkippedSourcesSucceeds(t *testing.T) {
	f := newArgsFixture(t)
	leaving := uint64(sweepFixtureBalance)
	result, err := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{"nat", "dest"}, ToRaw: "dest", LeavingRaw: &leaving,
	})
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	want := []sweepItemSummary{
		{From: argsNative, Skipped: "balance 5000000 <= leaving amount 5000000"},
		{From: argsDest, Skipped: "source and destination are the same account"},
	}
	if got := summarize(result.Items, argsDest, t); !reflect.DeepEqual(got, want) || result.FailureCount != 0 {
		t.Fatalf("items = %+v, failures %d\nwant    %+v and none", got, result.FailureCount, want)
	}
}

// With no source list, every signable account is swept, in the engine's order.
func TestSweepWithoutSourcesTakesEverySignableAccount(t *testing.T) {
	f := newArgsFixture(t)
	leaving := uint64(sweepFixtureBalance)
	result, err := f.app.Sweep(context.Background(), SweepRequest{AssetRef: "algo", ToRaw: "dest", LeavingRaw: &leaving})
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	signable := f.eng.GetSignableAddresses()
	if len(signable) == 0 || !result.UsedAllSignable || !reflect.DeepEqual(result.FromAddresses, signable) || len(result.Items) != len(signable) {
		t.Fatalf("swept %v (all signable: %v), want every signable account %v", result.FromAddresses, result.UsedAllSignable, signable)
	}
	for i, item := range result.Items {
		if item.From != signable[i] || item.SkippedReason == "" {
			t.Fatalf("item %d = %+v, want %s skipped", i, item, signable[i])
		}
	}
}

// How much an ALGO sweep leaves: a display amount when one is given, and
// otherwise each account's own minimum balance.
func TestSweepLeavingAmounts(t *testing.T) {
	f := newArgsFixture(t)
	result, err := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{"dest"}, ToRaw: "dest", LeavingText: "4.93",
	})
	if err != nil || result.Leaving.Raw != 4_930_000 || result.LeavingMinimumBalance {
		t.Fatalf("leaving 4.93: result %+v, error %v; want 4930000 base units", result, err)
	}
	result, err = f.app.Sweep(context.Background(), SweepRequest{AssetRef: "algo", FromRaw: []string{"dest"}, ToRaw: "dest"})
	if err != nil || result.Leaving.Raw != 0 || !result.LeavingMinimumBalance {
		t.Fatalf("leaving nothing: result %+v, error %v; want the minimum balance left", result, err)
	}
}

// An asset sweep sends each opted-in source's holding above what is to be
// left, as an asset transfer, and skips a source that is not opted in.
func TestSweepOfAnAsset(t *testing.T) {
	for _, tc := range []struct {
		name        string
		leavingText string
		fee         uint64
		useFlatFee  bool
		wantLeaving uint64
		wantSent    uint64
		wantFee     uint64
	}{
		{"leaving nothing by default", "", 0, false, 0, 500, 1_000},
		{"leaving a display amount", "1.25", 0, false, 125, 375, 1_000},
		{"with the request's flat fee", "", 3_000, true, 0, 500, 3_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgsFixture(t)
			knowSweepTestAsset(f)
			f.holdings = map[string][]models.AssetHolding{argsDest: holding(0), argsNative: holding(500)}
			result, err := f.app.Sweep(context.Background(), SweepRequest{
				AssetRef: "TST", FromRaw: []string{"nat", argsFalcon}, ToRaw: "dest", LeavingText: tc.leavingText,
				Fee: tc.fee, UseFlatFee: tc.useFlatFee, Wait: true,
			})
			if err == nil || err.Error() != "all 1 transaction(s) failed" {
				t.Fatalf("Sweep() error = %v, want the one transfer to fail at the signer", err)
			}
			want := []sweepItemSummary{
				{From: argsNative, ErrorPrefix: "transaction failed: ", Amount: tc.wantSent},
				{From: argsFalcon, Skipped: "account not opted into TST"},
			}
			if got := summarize(result.Items, argsDest, t); !reflect.DeepEqual(got, want) {
				t.Fatalf("items = %+v\nwant    %+v", got, want)
			}
			if !result.ReceiverOptedIn || result.LeavingMinimumBalance || result.Leaving.Raw != tc.wantLeaving || result.Asset.AssetID != sweepTestAsset {
				t.Fatalf("result header = %+v", result)
			}

			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.signs) != 1 || len(f.signs[0]) != 1 {
				t.Fatalf("/sign requests = %+v, want one with one transaction", f.signs)
			}
			txn, err := txnutil.DecodePrefixedHex(f.signs[0][0].TxnBytesHex)
			if err != nil {
				t.Fatal(err)
			}
			if txn.Type != types.AssetTransferTx || uint64(txn.XferAsset) != sweepTestAsset || txn.AssetAmount != tc.wantSent ||
				txn.AssetReceiver.String() != argsDest || txn.Sender.String() != argsNative || uint64(txn.Fee) != tc.wantFee {
				t.Fatalf("signed transaction = %+v, want a transfer of %d of asset %d from nat to dest with fee %d", txn, tc.wantSent, sweepTestAsset, tc.wantFee)
			}
		})
	}
}

// A destination typed as an address that looks like a known one is asked
// about before the asset is even resolved.
func TestSweepAsksAboutALookalikeDestination(t *testing.T) {
	real, fake := lookalikeAddresses()
	failed := errors.New("prompt closed")
	for _, tc := range []struct {
		name    string
		answer  bool
		err     error
		wantErr error
	}{
		{"declined", false, nil, ErrLookalikeDeclined},
		{"the question fails", true, failed, failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := lookalikeTestApp(t, map[string]string{"cold": real})
			var asked []RecipientLookalike
			result, err := app.Sweep(context.Background(), SweepRequest{
				AssetRef: "nosuchcoin", FromRaw: []string{real}, ToRaw: fake,
				ConfirmLookalikes: func(l []RecipientLookalike) (bool, error) { asked = l; return tc.answer, tc.err },
			})
			if result != nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("Sweep() = %+v, %v; want %v", result, err, tc.wantErr)
			}
			if len(asked) != 1 || asked[0].Typed != fake {
				t.Fatalf("asked about %+v, want the lookalike destination", asked)
			}
		})
	}
}

// A source whose payment is signed and accepted is recorded as sent. A sweep
// with one sent and one failed source is not a failed sweep.
func TestSweepCountsWhatWasSent(t *testing.T) {
	f := newArgsFixture(t)
	f.signsFor = map[string]bool{argsNative: true}
	leaving := uint64(4_000_000)
	result, err := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{"nat", argsFalcon}, ToRaw: "dest", LeavingRaw: &leaving,
	})
	if err != nil {
		t.Fatalf("Sweep() error = %v (items %+v)", err, result)
	}
	if len(result.Items) != 2 {
		t.Fatalf("items = %+v, want two", result.Items)
	}
	sent, failed := result.Items[0], result.Items[1]
	if sent.From != argsNative || sent.TxID == "" || sent.Error != "" || sent.SkippedReason != "" || sent.Amount.Raw != sweepFixtureBalance-4_000_000-1_000 {
		t.Fatalf("the signed source's item = %+v, want it sent", sent)
	}
	if failed.From != argsFalcon || !strings.HasPrefix(failed.Error, "transaction failed: ") || failed.TxID != "" {
		t.Fatalf("the unsigned source's item = %+v, want it failed", failed)
	}
	if result.SuccessCount != 1 || result.FailureCount != 1 || result.LastTxID != sent.TxID {
		t.Fatalf("successes %d, failures %d, last txid %q; want 1, 1 and %q", result.SuccessCount, result.FailureCount, result.LastTxID, sent.TxID)
	}
	if got := f.submitted.Load(); got != 1 {
		t.Fatalf("transactions the node accepted = %d, want 1", got)
	}
}

// A lookalike destination the user accepts, or is never asked about, is
// swept to, and the result carries the warning.
func TestSweepToAnAcceptedLookalikeWarns(t *testing.T) {
	real, fake := lookalikeAddresses()
	for _, tc := range []struct {
		name    string
		confirm func([]RecipientLookalike) (bool, error)
	}{
		{"accepted", func([]RecipientLookalike) (bool, error) { return true, nil }},
		{"never asked", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := lookalikeTestApp(t, map[string]string{"cold": real})
			leaving := uint64(0)
			result, _ := app.Sweep(context.Background(), SweepRequest{
				AssetRef: "algo", FromRaw: []string{fake}, ToRaw: fake, LeavingRaw: &leaving, ConfirmLookalikes: tc.confirm,
			})
			if result == nil || len(result.Warnings) != 1 || result.ToAddress != fake {
				t.Fatalf("Sweep() result = %+v, want a sweep to the lookalike with one warning", result)
			}
			if len(result.Items) != 1 || result.Items[0].SkippedReason != "source and destination are the same account" {
				t.Fatalf("items = %+v", result.Items)
			}
		})
	}
}

func TestSweepWithoutSourcesNeedsASignableAccount(t *testing.T) {
	real, _ := lookalikeAddresses()
	app := lookalikeTestApp(t, map[string]string{"cold": real})
	result, err := app.Sweep(context.Background(), SweepRequest{AssetRef: "algo", ToRaw: "cold"})
	if result != nil || err == nil || !strings.HasPrefix(err.Error(), "no signable accounts available.") {
		t.Fatalf("Sweep() = %+v, %v; want the no-signable-accounts error", result, err)
	}
}

// An account with no more than its minimum balance is skipped, and told so.
func TestSweepSkipsAnAccountAtItsMinimumBalance(t *testing.T) {
	f := newArgsFixture(t)
	f.unfunded = argsNative
	result, err := f.app.Sweep(context.Background(), SweepRequest{AssetRef: "algo", FromRaw: []string{"nat"}, ToRaw: "dest"})
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].SkippedReason != "balance 0 <= minimum balance 100000" {
		t.Fatalf("items = %+v, want the account skipped at its minimum balance", result.Items)
	}
}

// A submission the node refuses is recorded on its item and carried by the
// sweep's error. A failure before the submit is neither.
func TestSweepRecordsARefusedSubmission(t *testing.T) {
	leaving := uint64(4_000_000)
	req := SweepRequest{AssetRef: "algo", FromRaw: []string{"nat"}, ToRaw: "dest", LeavingRaw: &leaving}
	for _, tc := range []struct {
		name        string
		setup       func(f *argsFixture)
		wantRefused bool
	}{
		{"the node refuses the signed payment", func(f *argsFixture) {
			f.signsFor = map[string]bool{argsNative: true}
			f.rejectsSubmit = true
		}, true},
		{"the signer never signs", func(*argsFixture) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgsFixture(t)
			tc.setup(f)
			result, err := f.app.Sweep(context.Background(), req)
			if err == nil || err.Error() != "all 1 transaction(s) failed" || len(result.Items) != 1 {
				t.Fatalf("Sweep() = %+v, %v; want the one source to fail", result, err)
			}
			item := result.Items[0]
			if !strings.HasPrefix(item.Error, "transaction failed: ") || item.SimulationFailure != "" {
				t.Fatalf("item = %+v, want a failed transaction", item)
			}
			var failures appresult.SubmissionFailures
			if !errors.As(err, &failures) {
				t.Fatalf("error %T does not carry submission failures", err)
			}
			if refused := len(failures.SubmissionFailures()) == 1; refused != tc.wantRefused || (item.Submission != nil) != tc.wantRefused {
				t.Fatalf("submission failures = %d, item submission = %+v; want refused = %v",
					len(failures.SubmissionFailures()), item.Submission, tc.wantRefused)
			}
		})
	}
}
