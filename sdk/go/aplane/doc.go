// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

/*
Package aplane provides a Go client for signing Algorand transactions via apsignerd.

# Quick Start

	import (
		"github.com/aplane-algo/aplane/sdk/go/aplane"
		"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
		"github.com/algorand/go-algorand-sdk/v2/transaction"
	)

	// Connect to signer
	client, err := aplane.FromEnv(nil)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Build transaction with go-algorand-sdk
	algodClient, _ := algod.MakeClient("https://testnet-api.4160.nodely.dev", "")
	params, _ := algodClient.SuggestedParams().Do(context.Background())

	txn, _ := transaction.MakePaymentTxn(sender, receiver, 1000000, nil, "", params)

	// Sign via apsignerd (waits for operator approval)
	signed, err := client.SignTransaction(txn, "", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Submit using standard go-algorand-sdk
	signedBytes, _ := aplane.Base64ToBytes(signed)
	txid, _ := algodClient.SendRawTransaction(signedBytes).Do(context.Background())

# Connection Methods

Local connection:

	client := aplane.ConnectLocal("your-token", nil)

SSH tunnel connection:

	client, err := aplane.ConnectSSH(
		"signer.example.com",
		"your-token",
		"~/.ssh/id_ed25519",
		nil,
	)

From environment (reads ~/.aplane/config.yaml and aplane.token):

	client, err := aplane.FromEnv(nil)

# Signing

Single transaction:

	signed, err := client.SignTransaction(txn, "", nil)

Transaction group (do NOT pre-assign group IDs):

	signed, err := client.SignTransactions(
		[]types.Transaction{txn1, txn2},
		[]string{authAddr1, authAddr2},
		nil,
	)

With LogicSig runtime arguments:

	signed, err := client.SignTransaction(
		txn,
		hashlockAddress,
		aplane.LsigArgs{"preimage": preimageBytes},
	)
*/
package aplane
