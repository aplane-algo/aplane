// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignDummyTransaction signs a transaction with the embedded dummy LogicSig program.
// This encapsulates the knowledge of which TEAL program is used for dummies,
// keeping this detail out of the CLI layer.
//
// Returns the signed transaction as a types.SignedTxn.
func SignDummyTransaction(txn types.Transaction) (types.SignedTxn, error) {
	dummyLSig := types.LogicSig{Logic: EmbeddedDummyTealTok, Args: nil}
	_, signedBytes, err := crypto.SignLogicSigTransaction(dummyLSig, txn)
	if err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to sign dummy transaction: %w", err)
	}

	var stxn types.SignedTxn
	if err := msgpack.Decode(signedBytes, &stxn); err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to decode signed dummy transaction: %w", err)
	}

	return stxn, nil
}

// SignWithRawKey signs a transaction using a raw Ed25519 private key.
// This encapsulates the raw signing operation, keeping crypto imports out of the CLI layer.
//
// The expectedAddress parameter provides an optional safety check - if non-empty,
// the function verifies that the private key corresponds to this address before signing.
// This prevents signing with the wrong key.
//
// Parameters:
//   - txn: The transaction to sign
//   - privateKey: 64-byte Ed25519 private key (seed + public key format used by Algorand SDK)
//   - expectedAddress: Optional address to verify key matches (empty string skips verification)
//
// Returns the signed transaction as a types.SignedTxn.
func SignWithRawKey(txn types.Transaction, privateKey []byte, expectedAddress string) (types.SignedTxn, error) {
	// Create account from private key
	account, err := crypto.AccountFromPrivateKey(privateKey)
	if err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to create account from private key: %w", err)
	}

	// Verify address if expected address is provided
	if expectedAddress != "" && account.Address.String() != expectedAddress {
		return types.SignedTxn{}, fmt.Errorf("private key address mismatch: expected %s, got %s",
			expectedAddress, account.Address.String())
	}

	// Sign the transaction
	_, signedBytes, err := crypto.SignTransaction(account.PrivateKey, txn)
	if err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to sign transaction: %w", err)
	}

	var stxn types.SignedTxn
	if err := msgpack.Decode(signedBytes, &stxn); err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to decode signed transaction: %w", err)
	}

	return stxn, nil
}
