// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
)

func TestPreparePayment_NoAlgodClientError(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, _, err := eng.PreparePayment(context.Background(), SendPaymentParams{From: testAddr(1), To: testAddr(2), Amount: 1000})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPreparePayment_Success(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 10_000_000)  // 10 ALGO
	transport.addAccount(receiver, 1_000_000) // 1 ALGO
	eng := setupEngineWithMockAlgod(t, transport)

	result, balCheck, err := eng.PreparePayment(context.Background(), SendPaymentParams{
		From:   sender,
		To:     receiver,
		Amount: 1_000_000, // 1 ALGO
	})
	if err != nil || result == nil || balCheck == nil {
		t.Fatalf("PreparePayment() error = %v, result = %v, balCheck = %v", err, result, balCheck)
	}
	if result.Transaction.Type != "pay" {
		t.Errorf("txn type = %q, want %q", result.Transaction.Type, "pay")
	}
	if !balCheck.SufficientFunds {
		t.Error("should have sufficient funds")
	}
	if balCheck.NewAccount {
		t.Error("receiver should not be a new account")
	}
}

func TestPreparePayment_InsufficientFunds(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 100_000) // 0.1 ALGO
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, balCheck, err := eng.PreparePayment(context.Background(), SendPaymentParams{
		From:   sender,
		To:     receiver,
		Amount: 5_000_000, // 5 ALGO
	})
	if err != nil {
		t.Fatalf("PreparePayment() error = %v", err)
	}
	if balCheck.SufficientFunds {
		t.Error("should not have sufficient funds")
	}
}

func TestPreparePayment_NewReceiver(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 10_000_000)
	transport.addAccount(receiver, 0) // new account
	eng := setupEngineWithMockAlgod(t, transport)

	_, balCheck, err := eng.PreparePayment(context.Background(), SendPaymentParams{
		From:   sender,
		To:     receiver,
		Amount: 1_000_000,
	})
	if err != nil {
		t.Fatalf("PreparePayment() error = %v", err)
	}
	if !balCheck.NewAccount {
		t.Error("receiver should be a new account")
	}
}

func TestPreparePayment_BelowMinBalance(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 200_000) // 0.2 ALGO, min balance = 0.1
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, balCheck, err := eng.PreparePayment(context.Background(), SendPaymentParams{
		From:   sender,
		To:     receiver,
		Amount: 150_000, // 0.15 ALGO, leaves < min balance
	})
	if err != nil {
		t.Fatalf("PreparePayment() error = %v", err)
	}
	if !balCheck.BelowMinBalance {
		t.Error("should be below min balance after transfer")
	}
}

func TestPreparePayment_WithClose(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 10_000_000)
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, _, err := eng.PreparePayment(context.Background(), SendPaymentParams{
		From:   sender,
		To:     receiver,
		Amount: 0,
		Close:  true,
	})
	if err != nil {
		t.Fatalf("PreparePayment() error = %v", err)
	}
	if result.Transaction.CloseRemainderTo.IsZero() {
		t.Error("CloseRemainderTo should be set when Close=true")
	}
}

func TestPrepareClose_NoAlgodClientError(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, _, err := eng.PrepareClose(context.Background(), CloseAccountParams{From: testAddr(1), CloseTo: testAddr(2)})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareClose_AccountOnline(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Online", // online
	})
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, checkResult, err := eng.PrepareClose(context.Background(), CloseAccountParams{From: sender, CloseTo: receiver})
	if err == nil {
		t.Fatal("expected error for online account")
	}
	if checkResult == nil || !checkResult.IsOnline {
		t.Error("should report account is online")
	}
}

func TestPrepareClose_AccountHasASAs(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		Status:     "Offline",
		Assets:     []models.AssetHolding{{AssetId: 123, Amount: 100}},
	})
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, checkResult, err := eng.PrepareClose(context.Background(), CloseAccountParams{From: sender, CloseTo: receiver})
	if err == nil {
		t.Fatal("expected error for account with ASAs")
	}
	if checkResult == nil || !checkResult.HasASAs {
		t.Error("should report account has ASAs")
	}
}

func TestPrepareClose_ZeroBalance(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 0) // already empty
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, _, err := eng.PrepareClose(context.Background(), CloseAccountParams{From: sender, CloseTo: receiver})
	if err == nil {
		t.Fatal("expected error for zero balance")
	}
}

func TestPreparePayment_VerifyTxnFields(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 10_000_000)
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, _, err := eng.PreparePayment(context.Background(), SendPaymentParams{
		From:   sender,
		To:     receiver,
		Amount: 2_000_000,
		Note:   "test payment",
	})
	if err != nil || result == nil {
		t.Fatalf("PreparePayment() error = %v, result = %v", err, result)
	}

	txn := result.Transaction
	if txn.Type != "pay" {
		t.Errorf("txn.Type = %q, want %q", txn.Type, "pay")
	}
	if txn.Sender.String() != sender {
		t.Errorf("txn.Sender = %q, want %q", txn.Sender.String(), sender)
	}
	if txn.Receiver.String() != receiver {
		t.Errorf("txn.Receiver = %q, want %q", txn.Receiver.String(), receiver)
	}
	if txn.Amount != 2_000_000 {
		t.Errorf("txn.Amount = %d, want %d", txn.Amount, 2_000_000)
	}
	if string(txn.Note) != "test payment" {
		t.Errorf("txn.Note = %q, want %q", string(txn.Note), "test payment")
	}
	if !txn.CloseRemainderTo.IsZero() {
		t.Error("CloseRemainderTo should be zero when Close=false")
	}
}

func TestPreparePayment_FlatFee(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 10_000_000)
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, _, err := eng.PreparePayment(context.Background(), SendPaymentParams{
		From:       sender,
		To:         receiver,
		Amount:     1_000_000,
		Fee:        5000,
		UseFlatFee: true,
	})
	if err != nil {
		t.Fatalf("PreparePayment() error = %v", err)
	}

	if uint64(result.Transaction.Fee) != 5000 {
		t.Errorf("txn.Fee = %d, want 5000", result.Transaction.Fee)
	}
}

func TestPrepareClose_Success(t *testing.T) {
	sender := testAddr(1)
	receiver := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 5_000_000)
	transport.addAccount(receiver, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, checkResult, err := eng.PrepareClose(context.Background(), CloseAccountParams{From: sender, CloseTo: receiver})
	if err != nil || result == nil {
		t.Fatalf("PrepareClose() error = %v, result = %v", err, result)
	}
	if checkResult.Balance != 5_000_000 {
		t.Errorf("Balance = %d, want 5000000", checkResult.Balance)
	}
	if result.Transaction.CloseRemainderTo.IsZero() {
		t.Error("CloseRemainderTo should be set for close operation")
	}
	txn := result.Transaction
	if txn.Type != "pay" {
		t.Errorf("txn.Type = %q, want %q", txn.Type, "pay")
	}
	if txn.Amount != 0 {
		t.Errorf("txn.Amount = %d, want 0 for close", txn.Amount)
	}
}
