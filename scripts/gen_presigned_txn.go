// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

//go:build ignore

// Helper script to generate a pre-signed transaction for testing passthrough.
// Usage: go run scripts/gen_presigned_txn.go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func main() {
	// Generate a test account (or use existing mnemonic)
	account := crypto.GenerateAccount()
	mn, _ := mnemonic.FromPrivateKey(account.PrivateKey)

	fmt.Println("=== Test Account ===")
	fmt.Printf("Address: %s\n", account.Address.String())
	fmt.Printf("Mnemonic: %s\n", mn)
	fmt.Println()

	// Create a sample transaction
	// In real usage, you'd use actual network params
	sp := types.SuggestedParams{
		Fee:             1000,
		FirstRoundValid: 1000,
		LastRoundValid:  2000,
		GenesisID:       "testnet-v1.0",
		GenesisHash:     make([]byte, 32),
		FlatFee:         true,
	}
	sp.GenesisHash[0] = 0x01 // Dummy genesis hash

	txn, err := transaction.MakePaymentTxn(
		account.Address.String(),
		account.Address.String(), // Self-send for testing
		0,                        // 0 ALGO
		nil,
		"",
		sp,
	)
	if err != nil {
		panic(err)
	}

	// For grouped transactions, you'd set the group ID here
	// gid, _ := crypto.ComputeGroupID([]types.Transaction{txn, otherTxn})
	// txn.Group = gid

	// Sign the transaction
	_, stxnBytes, err := crypto.SignTransaction(account.PrivateKey, txn)
	if err != nil {
		panic(err)
	}

	// Encode as hex (this is what you'd put in signed_txn_hex)
	stxnHex := hex.EncodeToString(stxnBytes)

	fmt.Println("=== Signed Transaction (Ed25519) ===")
	fmt.Printf("signed_txn_hex: %s\n", stxnHex)
	fmt.Println()

	// Also show the unsigned transaction for comparison
	txnBytes := msgpack.Encode(txn)
	txnWithPrefix := append([]byte("TX"), txnBytes...)
	txnHex := hex.EncodeToString(txnWithPrefix)

	fmt.Println("=== Unsigned Transaction ===")
	fmt.Printf("txn_bytes_hex: %s\n", txnHex)
	fmt.Println()

	// Example curl command
	fmt.Println("=== Example: Mixed group with passthrough ===")
	fmt.Println(`curl -X POST http://localhost:8080/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: aplane YOUR_TOKEN" \
  -d '{
    "requests": [
      {"auth_address": "YOUR_SIGNER_ADDR", "txn_bytes_hex": "YOUR_UNSIGNED_TXN"},
      {"signed_txn_hex": "` + stxnHex + `"}
    ]
  }'`)
}
