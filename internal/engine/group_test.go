// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func testPreparedTxn(t *testing.T, from, to types.Address, note string) *TransactionPrepResult {
	t.Helper()

	sp := types.SuggestedParams{
		Fee:             1000,
		FlatFee:         true,
		FirstRoundValid: 1,
		LastRoundValid:  100,
		GenesisID:       "testnet-v1.0",
		GenesisHash:     []byte("12345678901234567890123456789012"),
	}

	txn, err := transaction.MakePaymentTxn(from.String(), to.String(), 1234, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	return &TransactionPrepResult{
		Transaction: txn,
		SigningContext: &SigningContext{
			Address:     from.String(),
			SigningAddr: from.String(),
			KeyType:     "ed25519",
		},
	}
}

func TestPrepareGroupRejectsEmpty(t *testing.T) {
	if _, err := PrepareGroup(); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error")
	}
}

func TestPrepareGroupRejectsSingle(t *testing.T) {
	prep := testPreparedTxn(t, testAddress(1), testAddress(2), "one")
	if _, err := PrepareGroup(prep); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error for single transaction")
	}
}

func TestPrepareGroupRejectsNilEntry(t *testing.T) {
	prep := testPreparedTxn(t, testAddress(1), testAddress(2), "one")
	if _, err := PrepareGroup(prep, nil); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error for nil entry")
	}
}

func TestPrepareGroupLeavesUngroupedAndPreservesMetadata(t *testing.T) {
	prep1 := testPreparedTxn(t, testAddress(1), testAddress(2), "first")
	prep2 := testPreparedTxn(t, testAddress(3), testAddress(4), "second")

	group, err := PrepareGroup(prep1, prep2)
	if err != nil {
		t.Fatalf("PrepareGroup() error = %v", err)
	}

	if len(group.Entries) != 2 {
		t.Fatalf("len(group.Entries) = %d, want 2", len(group.Entries))
	}

	// Group ID must NOT be assigned — the signer assigns it after adding
	// any required dummy transactions (e.g. for Falcon LogicSig budget).
	for i, entry := range group.Entries {
		if entry.Transaction.Group != (types.Digest{}) {
			t.Fatalf("entry %d has non-zero group ID %x, want ungrouped", i, entry.Transaction.Group)
		}
	}

	if string(group.Entries[0].Transaction.Note) != "first" || string(group.Entries[1].Transaction.Note) != "second" {
		t.Fatalf("transaction ordering was not preserved")
	}
	if group.Entries[0].SigningContext.Address != prep1.SigningContext.Address {
		t.Fatalf("signing context not preserved: got %s want %s", group.Entries[0].SigningContext.Address, prep1.SigningContext.Address)
	}
}

func TestPreparePaymentAndMethodCall_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := PreparePaymentMethodGroupWithContext(context.Background(), eng,
		SendPaymentParams{
			From:   testAddress(1).String(),
			To:     testAddress(2).String(),
			Amount: 1000,
		},
		MethodAppCallParams{
			ABIPath: testFixturePath(t, "testapp", "aplane_test.json"),
			Method:  "deposit",
			RawAppCallParams: RawAppCallParams{
				AppID: 123,
				From:  testAddress(1).String(),
			},
		},
	)
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}
