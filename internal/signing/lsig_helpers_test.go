// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestSignDummyTransaction tests signing with the embedded dummy LogicSig
func TestSignDummyTransaction(t *testing.T) {
	// Create a simple test transaction
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     types.Address{1, 2, 3},
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1000,
			LastValid:  2000,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{4, 5, 6},
			Amount:   types.MicroAlgos(100000),
		},
	}

	stxn, err := SignDummyTransaction(txn)
	if err != nil {
		t.Fatalf("SignDummyTransaction failed: %v", err)
	}

	// Verify the signed transaction has a LogicSig
	if len(stxn.Lsig.Logic) == 0 {
		t.Error("Signed transaction should have LogicSig program")
	}

	// Verify the LogicSig uses the embedded dummy TEAL
	if string(stxn.Lsig.Logic) != string(EmbeddedDummyTealTok) {
		t.Error("LogicSig should use embedded dummy TEAL")
	}

	// Verify no args (dummy doesn't need args)
	if len(stxn.Lsig.Args) != 0 {
		t.Error("Dummy LogicSig should have no args")
	}

	// Verify the transaction is preserved
	if stxn.Txn.Sender != txn.Sender {
		t.Error("Transaction sender should be preserved")
	}
}

// TestSignDummyTransaction_PreservesTransaction tests transaction preservation
func TestSignDummyTransaction_PreservesTransaction(t *testing.T) {
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      types.Address{1, 2, 3, 4, 5},
			Fee:         types.MicroAlgos(2000),
			FirstValid:  5000,
			LastValid:   6000,
			GenesisHash: types.Digest{9, 8, 7},
			Note:        []byte("test note"),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{6, 7, 8, 9, 10},
			Amount:   types.MicroAlgos(500000),
		},
	}

	stxn, err := SignDummyTransaction(txn)
	if err != nil {
		t.Fatalf("SignDummyTransaction failed: %v", err)
	}

	// Verify all fields are preserved
	if stxn.Txn.Sender != txn.Sender {
		t.Error("Sender not preserved")
	}
	if stxn.Txn.Fee != txn.Fee {
		t.Error("Fee not preserved")
	}
	if stxn.Txn.FirstValid != txn.FirstValid {
		t.Error("FirstValid not preserved")
	}
	if stxn.Txn.LastValid != txn.LastValid {
		t.Error("LastValid not preserved")
	}
	if stxn.Txn.Receiver != txn.Receiver {
		t.Error("Receiver not preserved")
	}
	if stxn.Txn.Amount != txn.Amount {
		t.Error("Amount not preserved")
	}
	if string(stxn.Txn.Note) != string(txn.Note) {
		t.Error("Note not preserved")
	}
}

// Note: contains() helper is defined in ed25519_test.go
