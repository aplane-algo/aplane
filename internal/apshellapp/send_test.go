// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestPrepareSendRejectsManyToMany(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.SetCache.Sets = map[string][]string{
		"senders": {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"},
		"rcvrs":   {"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"},
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.PrepareSend(context.Background(), SendRequest{
		AmountText: "1",
		AssetRef:   "algo",
		FromRaw:    []string{"@senders"},
		ToRaw:      []string{"@rcvrs"},
	})
	if err == nil {
		t.Fatal("PrepareSend() error = nil, want many-to-many rejection")
	}
}

func TestPrepareSendSelectsAtomicToMultipleMode(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{}
	eng.AliasCache.Aliases["alice"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	eng.SetCache.Sets = map[string][]string{
		"friends": {
			"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		},
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	plan, err := app.PrepareSend(context.Background(), SendRequest{
		AmountText: "1.5",
		AssetRef:   "algo",
		FromRaw:    []string{"alice"},
		ToRaw:      []string{"@friends"},
		Atomic:     true,
	})
	if err != nil {
		t.Fatalf("PrepareSend() error = %v", err)
	}
	if plan.Mode != SendModeAtomicToMultiple {
		t.Fatalf("Mode = %q, want %q", plan.Mode, SendModeAtomicToMultiple)
	}
	if len(plan.FromAddresses) != 1 || len(plan.ToAddresses) != 2 {
		t.Fatalf("plan addresses = %#v", plan)
	}
	if plan.Amount.Raw != 1500000 {
		t.Fatalf("Amount.Raw = %d, want 1500000", plan.Amount.Raw)
	}
}

func TestExecuteSendUsesNonAtomicPath(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"bob":   "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "1",
		AssetRef:   "algo",
		FromRaw:    []string{"alice"},
		ToRaw:      []string{"bob"},
	})
	if !errors.Is(err, engine.ErrNoAlgodClient) {
		t.Fatalf("ExecuteSend() error = %v, want %v", err, engine.ErrNoAlgodClient)
	}
}

func TestExecuteSendUsesAtomicPath(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}
	eng.SetCache.Sets = map[string][]string{
		"friends": {
			"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		},
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "1",
		AssetRef:   "algo",
		FromRaw:    []string{"alice"},
		ToRaw:      []string{"@friends"},
		Atomic:     true,
	})
	if !errors.Is(err, engine.ErrNoAlgodClient) {
		t.Fatalf("ExecuteSend() error = %v, want %v", err, engine.ErrNoAlgodClient)
	}
}

func TestAtomicValidationNotesRejectsTotalOverflow(t *testing.T) {
	const maxUint64 = ^uint64(0)

	plan := &AtomicSendPlan{
		Mode:   SendModeAtomicToMultiple,
		Amount: asa.Amount{Raw: maxUint64/2 + 1},
		To:     []string{"bob", "carol"},
		Checks: []BalanceCheckDetails{{SufficientFunds: false}},
	}

	_, err := atomicValidationNotes(plan)
	if err == nil {
		t.Fatal("atomicValidationNotes() error = nil, want overflow rejection")
	}
	if !strings.Contains(err.Error(), "overflows uint64") {
		t.Fatalf("atomicValidationNotes() error = %v, want overflow rejection", err)
	}
}

// TestAtomicValidationNotesChecksAlgoGroupTotal pins finding 2B: an ALGO
// atomic-to-multiple send validates the whole group's total against the
// balance, so a sender with enough for one leg but not all N is rejected at
// pre-flight rather than failing on-chain.
func TestAtomicValidationNotesChecksAlgoGroupTotal(t *testing.T) {
	// 5 ALGO to each of 3 receivers = 15 ALGO needed; sender has 8.
	// Checks[0].SufficientFunds is true for a single 5-ALGO payment.
	plan := &AtomicSendPlan{
		Mode:   SendModeAtomicToMultiple,
		Amount: asa.Amount{Raw: 5_000_000},
		To:     []string{"bob", "carol", "dave"},
		Checks: []BalanceCheckDetails{
			{SufficientFunds: true, SenderBalance: 8_000_000},
			{SufficientFunds: true, SenderBalance: 8_000_000},
			{SufficientFunds: true, SenderBalance: 8_000_000},
		},
	}

	_, err := atomicValidationNotes(plan)
	if err == nil {
		t.Fatal("atomicValidationNotes() error = nil, want group-total insufficiency")
	}
	if !strings.Contains(err.Error(), "insufficient balance") {
		t.Fatalf("atomicValidationNotes() error = %v, want insufficient balance", err)
	}

	// With enough for the whole group (20 ALGO), it passes.
	for i := range plan.Checks {
		plan.Checks[i].SenderBalance = 20_000_000
	}
	if _, err := atomicValidationNotes(plan); err != nil {
		t.Fatalf("atomicValidationNotes() error = %v, want success for sufficient total", err)
	}
}

// TestAtomicValidationNotesIncludesFees pins finding 2B's fee leg: the group
// total must include each transaction's fee, not just the amounts. A balance
// that covers the bare amounts but not amounts+fees is rejected at pre-flight
// rather than failing on-chain. 3 payments of 5 ALGO = 15 ALGO + 3 * 0.001
// ALGO of min fee = 15.003 ALGO needed; a 15.001-ALGO balance clears the
// amount-only sum (15.0) but not the fee-inclusive total.
func TestAtomicValidationNotesIncludesFees(t *testing.T) {
	plan := &AtomicSendPlan{
		Mode:   SendModeAtomicToMultiple,
		Amount: asa.Amount{Raw: 5_000_000},
		To:     []string{"bob", "carol", "dave"},
		Checks: []BalanceCheckDetails{
			{SufficientFunds: true, SenderBalance: 15_001_000},
			{SufficientFunds: true, SenderBalance: 15_001_000},
			{SufficientFunds: true, SenderBalance: 15_001_000},
		},
	}

	_, err := atomicValidationNotes(plan)
	if err == nil {
		t.Fatal("atomicValidationNotes() error = nil, want fee-inclusive insufficiency")
	}
	if !strings.Contains(err.Error(), "insufficient balance") {
		t.Fatalf("atomicValidationNotes() error = %v, want insufficient balance", err)
	}

	// Bumping the balance above the fee-inclusive total (15.003) clears it.
	for i := range plan.Checks {
		plan.Checks[i].SenderBalance = 15_004_000
	}
	if _, err := atomicValidationNotes(plan); err != nil {
		t.Fatalf("atomicValidationNotes() error = %v, want success once fees are covered", err)
	}
}

// TestAtomicValidationNotesUsesPreparedFees pins that the prepared
// transactions' actual fees are the source of truth over the GroupParams
// reconstruction: when the engine computed higher per-byte fees from suggested
// params (here 2000 each, 15.006 total), a balance that would clear the
// min-fee reconstruction (15.004 > 15.003) is still rejected.
func TestAtomicValidationNotesUsesPreparedFees(t *testing.T) {
	prep := &engine.AtomicPrepResult{
		Transactions: make([]types.Transaction, 3),
	}
	for i := range prep.Transactions {
		prep.Transactions[i].Fee = 2000
	}

	plan := &AtomicSendPlan{
		Mode:   SendModeAtomicToMultiple,
		Amount: asa.Amount{Raw: 5_000_000},
		To:     []string{"bob", "carol", "dave"},
		Prep:   preparedAtomicGroupFromEngine(prep),
		Checks: []BalanceCheckDetails{
			{SufficientFunds: true, SenderBalance: 15_004_000},
			{SufficientFunds: true, SenderBalance: 15_004_000},
			{SufficientFunds: true, SenderBalance: 15_004_000},
		},
	}

	_, err := atomicValidationNotes(plan)
	if err == nil {
		t.Fatal("atomicValidationNotes() error = nil, want prepared-fee insufficiency")
	}
	if !strings.Contains(err.Error(), "insufficient balance") {
		t.Fatalf("atomicValidationNotes() error = %v, want insufficient balance", err)
	}

	// Above the prepared-fee total (15.006), it passes.
	for i := range plan.Checks {
		plan.Checks[i].SenderBalance = 15_007_000
	}
	if _, err := atomicValidationNotes(plan); err != nil {
		t.Fatalf("atomicValidationNotes() error = %v, want success once prepared fees are covered", err)
	}
}

func TestCheckedSendTotal(t *testing.T) {
	const maxUint64 = ^uint64(0)

	tests := []struct {
		name   string
		amount uint64
		count  int
		want   uint64
		ok     bool
	}{
		{name: "zero count", amount: 10, count: 0, want: 0, ok: true},
		{name: "normal", amount: 10, count: 3, want: 30, ok: true},
		{name: "overflow", amount: maxUint64/2 + 1, count: 2, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := checkedSendTotal(tt.amount, tt.count)
			if ok != tt.ok {
				t.Fatalf("checkedSendTotal() ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("checkedSendTotal() = %d, want %d", got, tt.want)
			}
		})
	}
}

// An atomic send has no path that carries LogicSig arguments, so giving them
// is refused, not dropped.
func TestPrepareSendRefusesLogicSigArgsOnAnAtomicSend(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}
	eng.SetCache.Sets = map[string][]string{
		"friends": {
			"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		},
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())
	request := SendRequest{
		AmountText: "1.5", AssetRef: "algo", FromRaw: []string{"alice"}, ToRaw: []string{"@friends"},
		Atomic: true, LsigArgs: map[string][]byte{"preimage": []byte("x")},
	}
	if _, err := app.PrepareSend(context.Background(), request); err == nil || !strings.Contains(err.Error(), "atomic") {
		t.Fatalf("atomic send with arg: %v, want it refused", err)
	}
	request.Atomic = false
	if _, err := app.PrepareSend(context.Background(), request); err != nil {
		t.Fatalf("the same send without atomic is refused: %v", err)
	}
	// One to one takes the ordinary path, which carries the arguments, so
	// `atomic` there is no reason to refuse them.
	request.Atomic = true
	request.ToRaw = []string{"alice"}
	plan, err := app.PrepareSend(context.Background(), request)
	if err != nil || plan.Mode != SendModeNonAtomic {
		t.Fatalf("one-to-one send with atomic and arg: %v (mode %v), want the ordinary path", err, plan)
	}
}

// ASA preflight messages show balances in the asset's display units, the way
// the amount was typed, not its base units beside the unit name; ALGO shows in
// ALGO. Base units are compared as integers.
func TestPreflightMessagesUseDisplayUnits(t *testing.T) {
	usdc := asa.Metadata{AssetID: 31566704, UnitName: "USDC", Decimals: 6}

	err := validatePreparedSendItem(PreparedSendItem{BalanceCheck: &BalanceCheckDetails{
		SenderBalance: 1_500_000, RequiredAmount: 2_000_000,
	}}, asa.Amount{Meta: usdc, Raw: 2_000_000})
	if err == nil || err.Error() != "insufficient balance: have 1.500000, need 2.000000 USDC" {
		t.Fatalf("validatePreparedSendItem() error = %v", err)
	}

	plan := &AtomicSendPlan{
		Mode:   SendModeAtomicToMultiple,
		Amount: asa.Amount{Meta: usdc, Raw: 1_000_000},
		To:     []string{"bob", "carol"},
		Checks: []BalanceCheckDetails{
			{SufficientFunds: true, ReceiverOptedIn: true, SenderBalance: 2_500_000},
			{SufficientFunds: true, ReceiverOptedIn: true, SenderBalance: 2_500_000},
		},
	}
	notes, err := atomicValidationNotes(plan)
	if err != nil {
		t.Fatalf("atomicValidationNotes() error = %v", err)
	}
	if len(notes) == 0 || notes[0] != "Sender has 2.500000 USDC "+checkMark() {
		t.Fatalf("notes = %q, want the balance in USDC", notes)
	}
	for i := range plan.Checks {
		plan.Checks[i].SenderBalance = 1_500_000
	}
	if _, err := atomicValidationNotes(plan); err == nil || err.Error() != "insufficient balance: have 1.500000 USDC, need 2.000000 USDC" {
		t.Fatalf("atomicValidationNotes() error = %v", err)
	}

	// One base unit short past 2^54, where a float64 rounds both the balance
	// and the total to 2^54 and sees no difference.
	big := asa.Metadata{AssetID: 7, UnitName: "BIG", Decimals: 0}
	plan = &AtomicSendPlan{
		Mode:   SendModeAtomicToMultiple,
		Amount: asa.Amount{Meta: big, Raw: 1<<53 + 1},
		To:     []string{"bob", "carol"},
		Checks: []BalanceCheckDetails{
			{SufficientFunds: true, ReceiverOptedIn: true, SenderBalance: 1<<54 + 1},
			{SufficientFunds: true, ReceiverOptedIn: true, SenderBalance: 1<<54 + 1},
		},
	}
	if float64(plan.Checks[0].SenderBalance) < float64(2*plan.Amount.Raw) {
		t.Fatal("the case no longer defeats a float64 comparison; pick larger amounts")
	}
	if _, err := atomicValidationNotes(plan); err == nil || !strings.Contains(err.Error(), "insufficient balance") {
		t.Fatalf("atomicValidationNotes() error = %v, want one base unit short", err)
	}

	warnings := sendWarnings(PreparedSendItem{BalanceCheck: &BalanceCheckDetails{
		BelowMinBalance: true, RemainingBalance: 49_000, MinBalance: 100_000,
	}}, asa.Amount{Meta: asa.Metadata{UnitName: "ALGO", Decimals: 6}, Raw: 1})
	if len(warnings) != 1 || warnings[0].Message != "After this transaction, balance will be 0.049000 ALGO, below minimum balance of 0.100000 ALGO" {
		t.Fatalf("sendWarnings() = %+v", warnings)
	}
}

// An amount whose sum with the fee overflows is refused as before, and the
// message says so rather than printing the clamped requirement as if it were
// the real one.
func TestPreflightMessageForAnOverflowingRequirement(t *testing.T) {
	algo := asa.Metadata{UnitName: "ALGO", Decimals: 6}
	err := validatePreparedSendItem(PreparedSendItem{BalanceCheck: &BalanceCheckDetails{
		SenderBalance: 2_000_000, RequiredAmount: math.MaxUint64, RequiredOverflows: true,
	}}, asa.Amount{Meta: algo, Raw: math.MaxUint64 - 500})
	if err == nil {
		t.Fatal("validatePreparedSendItem() accepted an unfundable payment")
	}
	if want := "insufficient balance: have 2.000000 ALGO, and the amount plus fee exceeds the largest representable amount"; err.Error() != want {
		t.Fatalf("validatePreparedSendItem() error = %q, want %q", err, want)
	}
}
