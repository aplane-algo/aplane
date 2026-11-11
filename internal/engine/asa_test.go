// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
)

func TestFindAssetHolding(t *testing.T) {
	assets := []models.AssetHolding{
		{AssetId: 10, Amount: 100},
		{AssetId: 20, Amount: 200},
		{AssetId: 30, Amount: 0},
	}

	tests := []struct {
		name      string
		assetID   uint64
		wantAmt   uint64
		wantFound bool
	}{
		{"found with balance", 10, 100, true},
		{"found with different balance", 20, 200, true},
		{"found with zero balance", 30, 0, true},
		{"not found", 99, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			amt, found := findAssetHolding(assets, tc.assetID)
			if found != tc.wantFound {
				t.Errorf("found = %v, want %v", found, tc.wantFound)
			}
			if amt != tc.wantAmt {
				t.Errorf("amount = %d, want %d", amt, tc.wantAmt)
			}
		})
	}

	t.Run("empty slice", func(t *testing.T) {
		_, found := findAssetHolding(nil, 10)
		if found {
			t.Error("should not find in empty slice")
		}
	})
}

func TestPrepareOptIn_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, err := eng.PrepareOptIn(context.Background(), OptInParams{Account: testAddr(1), AssetID: 10})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareOptOut_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, _, err := eng.PrepareOptOut(context.Background(), OptOutParams{Account: testAddr(1), AssetID: 10})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareASATransfer_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, _, err := eng.PrepareASATransfer(context.Background(), SendASAParams{From: testAddr(1), To: testAddr(2), AssetID: 10, Amount: 1})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareOptOut_NotOptedIn(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	// Account has no assets
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, checkResult, err := eng.PrepareOptOut(context.Background(), OptOutParams{Account: addr, AssetID: 42})
	if err == nil {
		t.Fatal("expected error for not opted in")
	}
	if checkResult == nil || checkResult.IsOptedIn {
		t.Error("should report not opted in")
	}
}

func TestPrepareOptOut_BalanceRequiresCloseTo(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    addr,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 42, Amount: 500}},
	})
	eng := setupEngineWithMockAlgod(t, transport)

	_, checkResult, err := eng.PrepareOptOut(context.Background(), OptOutParams{Account: addr, AssetID: 42})
	if err == nil {
		t.Fatal("expected error when balance > 0 and no CloseTo")
	}
	if checkResult == nil || !checkResult.NeedsCloseTo {
		t.Error("should report needs close-to")
	}
	if checkResult.AssetBalance != 500 {
		t.Errorf("AssetBalance = %d, want 500", checkResult.AssetBalance)
	}
}

func TestPrepareOptOut_ZeroBalance_ImplicitSelf(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    addr,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 42, Amount: 0}},
	})
	eng := setupEngineWithMockAlgod(t, transport)

	result, checkResult, err := eng.PrepareOptOut(context.Background(), OptOutParams{Account: addr, AssetID: 42})
	if err != nil || result == nil {
		t.Fatalf("PrepareOptOut() error = %v, result = %v", err, result)
	}
	if !checkResult.UsingImplicitSelf {
		t.Error("should use implicit self as close-to for zero balance")
	}
	if result.Transaction.Type != "axfer" {
		t.Errorf("txn.Type = %q, want %q", result.Transaction.Type, "axfer")
	}
}

func TestPrepareOptOut_CloseToNotOptedIn(t *testing.T) {
	addr := testAddr(1)
	closeTo := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    addr,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 42, Amount: 500}},
	})
	transport.addAccount(closeTo, 1_000_000) // closeTo has no assets
	eng := setupEngineWithMockAlgod(t, transport)

	_, _, err := eng.PrepareOptOut(context.Background(), OptOutParams{Account: addr, AssetID: 42, CloseTo: closeTo})
	if err == nil {
		t.Fatal("expected error when close-to is not opted in")
	}
}

func TestCheckASABalances_SenderNotOptedIn(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 1_000_000) // no assets
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, err := eng.checkASABalances(context.Background(), sender, receiver, 42, 100)
	if err == nil {
		t.Fatal("expected error for sender not opted in")
	}
}

func TestCheckASABalances_Success(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 42, Amount: 1000}},
	})
	transport.addAccountFull(models.Account{
		Address:    receiver,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 42, Amount: 0}},
	})
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.checkASABalances(context.Background(), sender, receiver, 42, 500)
	if err != nil {
		t.Fatalf("checkASABalances() error = %v", err)
	}
	if !result.SufficientFunds {
		t.Error("should have sufficient funds")
	}
	if !result.ReceiverOptedIn {
		t.Error("receiver should be opted in")
	}
}

func TestCheckASABalances_InsufficientFunds(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 42, Amount: 100}},
	})
	transport.addAccountFull(models.Account{
		Address:    receiver,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 42, Amount: 0}},
	})
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.checkASABalances(context.Background(), sender, receiver, 42, 500)
	if err != nil {
		t.Fatalf("checkASABalances() error = %v", err)
	}
	if result.SufficientFunds {
		t.Error("should not have sufficient funds (100 < 500)")
	}
}

func TestCheckASABalances_ReceiverNotOptedIn(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 42, Amount: 1000}},
	})
	transport.addAccount(receiver, 1_000_000) // no assets
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.checkASABalances(context.Background(), sender, receiver, 42, 100)
	if err != nil {
		t.Fatalf("checkASABalances() error = %v", err)
	}
	if result.ReceiverOptedIn {
		t.Error("receiver should not be opted in")
	}
}

// A payment's balance check is exact in microAlgos, and an amount whose sum
// with the fee overflows is unfundable rather than wrapping to a small
// requirement the sender appears to meet.
func TestCheckPaymentBalancesIsExactAndOverflowSafe(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)
	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{Address: sender, Amount: 2_001_000, MinBalance: 100_000, Status: "Offline"})
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.checkPaymentBalances(context.Background(), sender, receiver, 2_000_000, 1_000, true)
	if err != nil {
		t.Fatalf("checkPaymentBalances() error = %v", err)
	}
	if !result.SufficientFunds || result.SenderBalance != 2_001_000 || result.RequiredAmount != 2_001_000 || result.RemainingBalance != 0 || !result.BelowMinBalance {
		t.Fatalf("exact balance: %+v", result)
	}
	result, err = eng.checkPaymentBalances(context.Background(), sender, receiver, 2_000_001, 1_000, true)
	if err != nil {
		t.Fatalf("checkPaymentBalances() error = %v", err)
	}
	if result.SufficientFunds || result.RequiredAmount != 2_001_001 || result.RequiredOverflows {
		t.Fatalf("one microAlgo short: %+v", result)
	}

	result, err = eng.checkPaymentBalances(context.Background(), sender, receiver, math.MaxUint64-500, 1_000, true)
	if err != nil {
		t.Fatalf("checkPaymentBalances() error = %v", err)
	}
	if result.SufficientFunds || !result.BelowMinBalance || result.RemainingBalance != 0 || !result.RequiredOverflows {
		t.Fatalf("overflowing amount and fee: %+v", result)
	}
}

// An ASA balance check reports base units exactly: past 2^53 a float64 would
// have rounded the balance and the amount to the same value.
func TestCheckASABalancesComparesLargeAmountsExactly(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)
	const held = uint64(1) << 53
	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address: sender, Amount: 1_000_000, MinBalance: 100_000, Status: "Offline",
		Assets: []models.AssetHolding{{AssetId: 42, Amount: held}},
	})
	transport.addAccountFull(models.Account{
		Address: receiver, Amount: 1_000_000, MinBalance: 100_000, Status: "Offline",
		Assets: []models.AssetHolding{{AssetId: 42, Amount: 0}},
	})
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.checkASABalances(context.Background(), sender, receiver, 42, held+1)
	if err != nil {
		t.Fatalf("checkASABalances() error = %v", err)
	}
	if result.SufficientFunds || result.SenderBalance != held || result.RequiredAmount != held+1 {
		t.Fatalf("one base unit short past 2^53: %+v", result)
	}
}
