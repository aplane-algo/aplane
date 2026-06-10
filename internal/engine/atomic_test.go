// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"testing"
)

func TestPrepareAtomicPayments_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, err := eng.PrepareAtomicPayments(context.Background(), []AtomicPaymentParams{{From: testAddr(1), To: testAddr(2), Amount: 1000}}, AtomicGroupParams{})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareAtomicPayments_Empty(t *testing.T) {
	transport := newAccountMockTransport(t)
	transport.addAccount(testAddr(1), 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, err := eng.PrepareAtomicPayments(context.Background(), nil, AtomicGroupParams{})
	if err == nil {
		t.Fatal("expected error for empty payments")
	}
}

func TestPrepareAtomicASATransfers_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, err := eng.PrepareAtomicASATransfers(context.Background(), []AtomicASAParams{{From: testAddr(1), To: testAddr(2), AssetID: 10, Amount: 1}}, AtomicGroupParams{})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareAtomicASATransfers_Empty(t *testing.T) {
	transport := newAccountMockTransport(t)
	transport.addAccount(testAddr(1), 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, err := eng.PrepareAtomicASATransfers(context.Background(), nil, AtomicGroupParams{})
	if err == nil {
		t.Fatal("expected error for empty transfers")
	}
}

func TestPrepareAtomicPayments_Success(t *testing.T) {
	addr1 := testAddr(1)
	addr2 := testAddr(2)
	addr3 := testAddr(3)

	transport := newAccountMockTransport(t)
	transport.addAccount(addr1, 10_000_000)
	transport.addAccount(addr2, 1_000_000)
	transport.addAccount(addr3, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.PrepareAtomicPayments(context.Background(), []AtomicPaymentParams{
		{From: addr1, To: addr2, Amount: 1_000_000, Note: "payment 1"},
		{From: addr1, To: addr3, Amount: 2_000_000, Note: "payment 2"},
	}, AtomicGroupParams{})
	if err != nil {
		t.Fatalf("PrepareAtomicPayments() error = %v", err)
	}

	if len(result.Transactions) != 2 {
		t.Fatalf("expected 2 transactions, got %d", len(result.Transactions))
	}
	if len(result.SigningContexts) != 2 {
		t.Fatalf("expected 2 signing contexts, got %d", len(result.SigningContexts))
	}

	// Verify first transaction
	if result.Transactions[0].Receiver.String() != addr2 {
		t.Errorf("txn[0].Receiver = %q, want %q", result.Transactions[0].Receiver.String(), addr2)
	}
	if result.Transactions[0].Amount != 1_000_000 {
		t.Errorf("txn[0].Amount = %d, want 1000000", result.Transactions[0].Amount)
	}

	// Verify second transaction
	if result.Transactions[1].Receiver.String() != addr3 {
		t.Errorf("txn[1].Receiver = %q, want %q", result.Transactions[1].Receiver.String(), addr3)
	}
	if result.Transactions[1].Amount != 2_000_000 {
		t.Errorf("txn[1].Amount = %d, want 2000000", result.Transactions[1].Amount)
	}
}

func TestPrepareAtomicPayments_WithFlatFee(t *testing.T) {
	addr1 := testAddr(1)
	addr2 := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(addr1, 10_000_000)
	transport.addAccount(addr2, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.PrepareAtomicPayments(context.Background(), []AtomicPaymentParams{
		{From: addr1, To: addr2, Amount: 1_000_000},
	}, AtomicGroupParams{Fee: 3000, UseFlatFee: true})
	if err != nil {
		t.Fatalf("PrepareAtomicPayments() error = %v", err)
	}
	if uint64(result.Transactions[0].Fee) != 3000 {
		t.Errorf("txn.Fee = %d, want 3000", result.Transactions[0].Fee)
	}
}
