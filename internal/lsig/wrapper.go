// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package lsig provides transaction wrapping utilities for large post-quantum signatures.
//
// Post-quantum signatures (e.g., Falcon ~1280 bytes) exceed Algorand's 1000-byte
// LogicSig limit per transaction. This package provides dummy transaction wrapping
// to spread the signature cost across multiple transactions in a group.
//
// For cryptographic operations (signing, key generation, derivation), use
// internal/logicsigdsa instead.
package lsig

import (
	_ "embed"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

//go:embed dummy.teal.tok
var EmbeddedDummyTealTok []byte

// TxLsigBudget is Algorand's LogicSig pool budget contribution per transaction in a group
const TxLsigBudget = 1000

// CreateDummyTransactions creates the specified number of dummy self-payment transactions
func CreateDummyTransactions(count int, sp types.SuggestedParams) ([]types.Transaction, error) {
	if count == 0 {
		return nil, nil
	}

	// Create dummy LogicSig account with embedded TEAL
	dummyLSig := types.LogicSig{Logic: EmbeddedDummyTealTok, Args: nil}
	lsigAcct := crypto.LogicSigAccount{Lsig: dummyLSig}
	dummyAddr, err := lsigAcct.Address()
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

	dummyLSig := types.LogicSig{Logic: EmbeddedDummyTealTok, Args: nil}
	signedDummies := make([][]byte, len(dummyTxns))

	for i, txn := range dummyTxns {
		_, signedBytes, err := crypto.SignLogicSigTransaction(dummyLSig, txn)
		if err != nil {
			return nil, fmt.Errorf("failed to sign dummy txn %d: %w", i+1, err)
		}
		signedDummies[i] = signedBytes
	}

	return signedDummies, nil
}
