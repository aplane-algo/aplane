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

// SignTransactionWithKey signs txn with an Ed25519 private key held in memory
// and returns the transaction ID and the encoded signed transaction. When the
// key's address differs from the sender's, that address becomes the AuthAddr,
// exactly as the Algorand SDK's deprecated crypto.SignTransaction did. It goes
// through the SDK's current signer API, so callers that already hold the key
// avoid the deprecated entry point.
func SignTransactionWithKey(privateKey ed25519.PrivateKey, txn types.Transaction) (string, []byte, error) {
	signer, err := crypto.SKToInMemorySigner(privateKey)
	if err != nil {
		return "", nil, err
	}
	return transaction.SignTransaction(transaction.Ed25519AccountTransactionSigner{Signer: signer}, txn)
}
