// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
)

func testPreparedTxn(t *testing.T, from, to types.Address, note string, lsigArgs map[string][]byte) *TransactionPrepResult {
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
		LsigArgs: lsigArgs,
	}
}

func TestPrepareGroupRejectsEmpty(t *testing.T) {
	if _, err := PrepareGroup(); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error")
	}
}

func TestPrepareGroupRejectsSingle(t *testing.T) {
	prep := testPreparedTxn(t, testAddress(1), testAddress(2), "one", nil)
	if _, err := PrepareGroup(prep); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error for single transaction")
	}
}

func TestPrepareGroupRejectsNilEntry(t *testing.T) {
	prep := testPreparedTxn(t, testAddress(1), testAddress(2), "one", nil)
	if _, err := PrepareGroup(prep, nil); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error for nil entry")
	}
}

func TestPrepareGroupLeavesUngroupedAndPreservesMetadata(t *testing.T) {
	prep1 := testPreparedTxn(t, testAddress(1), testAddress(2), "first", map[string][]byte{"foo": []byte("bar")})
	prep2 := testPreparedTxn(t, testAddress(3), testAddress(4), "second", nil)

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
	if string(group.LsigArgsMap()[0]["foo"]) != "bar" {
		t.Fatalf("lsig args not preserved: %+v", group.LsigArgsMap())
	}
	if group.LsigArgsMap()[1] != nil {
		t.Fatalf("unexpected lsig args for second entry: %+v", group.LsigArgsMap()[1])
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

func TestExecutePreparedGroupValidatesLsigArgsBeforeSubmit(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	lsigAddr := testAddress(1).String()
	eng.SignerCache.SetGenericLsig(lsigAddr, true)
	eng.SignerCache.SetSigningArgs(lsigAddr, []cache.SigningArgInfo{
		{Name: "preimage", Type: "bytes", Required: true},
	})

	prep1 := testPreparedTxn(t, testAddress(1), testAddress(2), "first", nil)
	prep2 := testPreparedTxn(t, testAddress(3), testAddress(4), "second", nil)

	group, err := PrepareGroup(prep1, prep2)
	if err != nil {
		t.Fatalf("PrepareGroup() error = %v", err)
	}

	_, err = eng.ExecutePreparedGroupWithContext(context.Background(), group, false)
	if err == nil {
		t.Fatal("ExecutePreparedGroup() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "transaction 1: invalid LogicSig arguments: missing required argument: preimage") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSubmitLsigArgsAcceptsValidArgs(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	lsigAddr := testAddress(1).String()
	eng.SignerCache.SetGenericLsig(lsigAddr, true)
	eng.SignerCache.SetSigningArgs(lsigAddr, []cache.SigningArgInfo{
		{Name: "preimage", Type: "bytes", Required: true},
	})

	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "first", map[string][]byte{"preimage": []byte("ok")}).Transaction
	if err := eng.validateSubmitLsigArgs([]types.Transaction{txn}, []map[string][]byte{{"preimage": []byte("ok")}}); err != nil {
		t.Fatalf("validateSubmitLsigArgs() error = %v", err)
	}
}
