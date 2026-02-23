// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	"context"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SubmitTransactions submits signed transactions to the network
func SubmitTransactions(
	signedTxns [][]byte,
	algodClient *algod.Client,
	waitForConfirmation bool,
) ([]string, error) {
	if len(signedTxns) == 0 {
		return nil, fmt.Errorf("no signed transactions to submit")
	}

	fmt.Println("\nSubmitting to network...")

	var txIDs []string
	isGroup := len(signedTxns) > 1

	if isGroup {
		// For atomic groups, concatenate all signed transactions into a single blob
		// This is required for Algorand to properly validate the group
		var blob []byte
		for _, signedTxn := range signedTxns {
			blob = append(blob, signedTxn...)
		}

		// Compute all transaction IDs before submitting
		for _, signedTxn := range signedTxns {
			var stxn types.SignedTxn
			if err := msgpack.Decode(signedTxn, &stxn); err != nil {
				return nil, fmt.Errorf("failed to decode signed transaction: %w", err)
			}
			txID := crypto.GetTxID(stxn.Txn)
			txIDs = append(txIDs, txID)
		}

		// Submit the entire group as a single blob
		_, err := algodClient.SendRawTransaction(blob).Do(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to submit transaction group: %w", cleanSubmitError(err))
		}
	} else {
		// Submit single transaction
		var stxn types.SignedTxn
		if err := msgpack.Decode(signedTxns[0], &stxn); err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction: %w", err)
		}
		txID := crypto.GetTxID(stxn.Txn)
		txIDs = append(txIDs, txID)

		_, err := algodClient.SendRawTransaction(signedTxns[0]).Do(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to submit transaction: %w", cleanSubmitError(err))
		}
	}

	fmt.Println("✓ Transaction(s) submitted")
	fmt.Println("\nTransaction IDs:")
	for i, txID := range txIDs {
		fmt.Printf("  %d. %s\n", i+1, txID)
	}

	// Wait for confirmation if requested
	if waitForConfirmation && len(txIDs) > 0 {
		// For atomic groups, waiting on first txID confirms the whole group
		fmt.Print("Waiting for confirmation")
		confirmedTxn, err := transaction.WaitForConfirmation(algodClient, txIDs[0], 4, context.Background())
		if err != nil {
			fmt.Println()
			return txIDs, fmt.Errorf("confirmation failed: %w", err)
		}
		fmt.Printf("\n✓ Confirmed in round %d\n", confirmedTxn.ConfirmedRound)
	}

	return txIDs, nil
}

// cleanSubmitError extracts a clean rejection reason from Algorand node errors.
// Node responses include the full serialized transaction struct in the message,
// producing enormous output. This extracts just the rejection reason.
func cleanSubmitError(err error) error {
	msg := err.Error()
	// Node error format: "...{struct dump} invalid : transaction TXID: <reason>..."
	if idx := strings.LastIndex(msg, "invalid : "); idx != -1 {
		clean := msg[idx+len("invalid : "):]
		clean = strings.TrimSuffix(clean, "\"}")
		clean = strings.TrimSuffix(clean, "\"")
		return fmt.Errorf("%s", clean)
	}
	return err
}
