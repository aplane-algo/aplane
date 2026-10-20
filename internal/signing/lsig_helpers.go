// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"crypto/ed25519"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignDummyTransaction signs a transaction with the embedded dummy LogicSig program.
// This encapsulates the knowledge of which TEAL program is used for dummies,
// keeping this detail out of the CLI layer.
//
// Returns the signed transaction as a types.SignedTxn.
func SignDummyTransaction(txn types.Transaction) (types.SignedTxn, error) {
	signedBytes, err := signDummyTransactionBytes(txn)
	if err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to sign dummy transaction: %w", err)
	}

	var stxn types.SignedTxn
	if err := msgpack.Decode(signedBytes, &stxn); err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to decode signed dummy transaction: %w", err)
	}

	return stxn, nil
}

func dummyLogicSig() types.LogicSig {
	return types.LogicSig{Logic: EmbeddedDummyTealTok}
}

func signDummyTransactionBytes(txn types.Transaction) ([]byte, error) {
	_, signedBytes, err := crypto.SignLogicSigTransaction(dummyLogicSig(), txn)
	return signedBytes, err
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
	_, signedBytes, err := SignTransactionWithKey(account.PrivateKey, txn)
	if err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to sign transaction: %w", err)
	}

	var stxn types.SignedTxn
	if err := msgpack.Decode(signedBytes, &stxn); err != nil {
		return types.SignedTxn{}, fmt.Errorf("failed to decode signed transaction: %w", err)
	}

	return stxn, nil
}

// SignTransactionWithKey signs txn with an Ed25519 private key held in memory
// and returns the transaction ID and the encoded signed transaction. When the
// key's address differs from the sender's, that address becomes the AuthAddr,
// exactly as the Algorand SDK's deprecated crypto.SignTransaction did. It goes
// through the SDK's current signer API, so callers that already hold the key
// (the raw-key path and tests) avoid the deprecated entry point.
func SignTransactionWithKey(privateKey ed25519.PrivateKey, txn types.Transaction) (string, []byte, error) {
	signer, err := crypto.SKToInMemorySigner(privateKey)
	if err != nil {
		return "", nil, err
	}
	return transaction.SignTransaction(transaction.Ed25519AccountTransactionSigner{Signer: signer}, txn)
}
