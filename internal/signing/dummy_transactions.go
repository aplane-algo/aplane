// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TxLsigBudget is Algorand's LogicSig pool budget contribution per transaction in a group
const TxLsigBudget = 1000

// DummyAddress returns the address authorized by the embedded dummy LogicSig.
func DummyAddress() (types.Address, error) {
	lsigAcct := crypto.LogicSigAccount{Lsig: dummyLogicSig()}
	return lsigAcct.Address()
}

// CreateDummyTransactions creates the specified number of dummy self-payment transactions
func CreateDummyTransactions(count int, sp types.SuggestedParams) ([]types.Transaction, error) {
	if count == 0 {
		return nil, nil
	}

	dummyAddr, err := DummyAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to compute dummy address: %w", err)
	}

	dummyTxns := make([]types.Transaction, count)

	for i := 0; i < count; i++ {
		// Create self-payment with unique note
		txn, err := transaction.MakePaymentTxn(
			dummyAddr.String(),
			dummyAddr.String(),
			0,
			[]byte{byte(i)}, // Unique note for each dummy
			"",
			sp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create dummy transaction %d: %w", i+1, err)
		}

		// Set fee to 0 (first transaction pays for all)
		txn.Fee = 0

		dummyTxns[i] = txn
	}

	return dummyTxns, nil
}

// SignDummyTransactions signs dummy transactions with their LogicSig
func SignDummyTransactions(dummyTxns []types.Transaction) ([][]byte, error) {
	if len(dummyTxns) == 0 {
		return nil, nil
	}

	signedDummies := make([][]byte, len(dummyTxns))

	for i, txn := range dummyTxns {
		signedBytes, err := signDummyTransactionBytes(txn)
		if err != nil {
			return nil, fmt.Errorf("failed to sign dummy txn %d: %w", i+1, err)
		}
		signedDummies[i] = signedBytes
	}

	return signedDummies, nil
}

// IsSignerAddedDummy reports whether dummy is the index'th LogicSig-budget
// dummy the signer appends after original: a zero-fee, zero-amount payment
// from and to the dummy address, on original's network and validity window
// and in its group, with the index as its one-byte note.
func IsSignerAddedDummy(dummy, original types.Transaction, index int) bool {
	if dummy.Type != types.PaymentTx {
		return false
	}
	dummyAddr, err := DummyAddress()
	if err != nil {
		return false
	}
	if dummy.Sender != dummyAddr || dummy.Receiver != dummyAddr || dummy.Amount != 0 {
		return false
	}
	if dummy.Fee != 0 || !dummy.RekeyTo.IsZero() || !dummy.CloseRemainderTo.IsZero() {
		return false
	}
	if dummy.GenesisID != original.GenesisID || dummy.GenesisHash != original.GenesisHash {
		return false
	}
	if dummy.FirstValid != original.FirstValid || dummy.LastValid != original.LastValid {
		return false
	}
	if original.Group == (types.Digest{}) || dummy.Group != original.Group {
		return false
	}
	if len(dummy.Note) != 1 || dummy.Note[0] != byte(index) {
		return false
	}
	if dummy.Lease != ([32]byte{}) {
		return false
	}
	return true
}
