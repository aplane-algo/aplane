// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/util"
)

// SubmitOptions bundles optional parameters for SignAndSubmitViaGroup.
type SubmitOptions struct {
	WaitForConfirmation bool
	Verbose             bool
	LsigArgsMap         []map[string][]byte
	Simulate            bool
	// TxnWriter is called for each original transaction after successful
	// submission or simulation. If nil, no callback is made.
	// Parameters: transaction, transaction ID.
	TxnWriter func(txn types.Transaction, txID string)
}

// SignAndSubmitViaGroup signs and submits transactions using the /sign endpoint.
// This is the simplified flow where the server handles:
// - Dummy transaction creation for LSig budget
// - Fee pooling across LSig transactions
// - Group ID computation
//
// The client only needs to build transactions with suggested params and send them.
// Returns transaction IDs and an error. Returns ErrSimulationFailed when simulation
// detects a transaction failure.
func SignAndSubmitViaGroup(
	txns []types.Transaction,
	authCache *util.AuthAddressCache,
	signerClient *util.SignerClient,
	algodClient *algod.Client,
	opts SubmitOptions,
) ([]string, error) {
	if len(txns) == 0 {
		return nil, fmt.Errorf("no transactions provided")
	}

	if signerClient == nil {
		return nil, fmt.Errorf("not connected to Signer")
	}

	// Build sign requests
	requests := make([]util.SignRequest, len(txns))
	for i, txn := range txns {
		sender := txn.Sender.String()
		effectiveSigner := authCache.ResolveEffectiveSigner(sender)

		// Encode transaction (TX prefix + msgpack)
		txnBytes := append([]byte("TX"), msgpack.Encode(txn)...)

		// Convert lsigArgs to hex if present
		var lsigArgsHex map[string]string
		if i < len(opts.LsigArgsMap) && opts.LsigArgsMap[i] != nil {
			lsigArgsHex = make(map[string]string)
			for name, value := range opts.LsigArgsMap[i] {
				lsigArgsHex[name] = hex.EncodeToString(value)
			}
		}

		requests[i] = util.SignRequest{
			AuthAddress: effectiveSigner,
			TxnSender:   sender,
			TxnBytesHex: hex.EncodeToString(txnBytes),
			LsigArgs:    lsigArgsHex,
		}

		if opts.Verbose {
			fmt.Printf("  Transaction %d: %s → %s\n", i+1, sender[:8]+"...", FormatTransactionSummary(txn, nil))
		}
	}

	if opts.Verbose {
		fmt.Printf("Sending %d transaction(s) to /sign...\n", len(txns))
	}

	// Send to /sign endpoint
	resp, err := signerClient.RequestGroupSign(requests)
	if err != nil {
		return nil, err
	}

	// Decode signed transactions from hex
	signedTxns := make([][]byte, len(resp.Signed))
	for i, hexStr := range resp.Signed {
		signedBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
		}
		signedTxns[i] = signedBytes
	}

	if opts.Verbose {
		dummyCount := len(signedTxns) - len(txns)
		if dummyCount > 0 {
			fmt.Printf("✓ Signed %d main + %d dummy transaction(s)\n", len(txns), dummyCount)
		} else {
			fmt.Printf("✓ Signed %d transaction(s)\n", len(txns))
		}
	}

	// Submit or simulate
	var txIDs []string
	if opts.Simulate {
		txIDs, err = SimulateTransactions(signedTxns, algodClient)
	} else {
		txIDs, err = SubmitTransactions(signedTxns, algodClient, opts.WaitForConfirmation)
	}
	if err != nil {
		return txIDs, err
	}

	// Invoke TxnWriter callback for each original transaction (not dummies)
	if opts.TxnWriter != nil {
		for i, txn := range txns {
			if i < len(txIDs) {
				opts.TxnWriter(txn, txIDs[i])
			}
		}
	}

	return txIDs, nil
}
