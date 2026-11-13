// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func SubmitTransactionsWithContext(
	ctx context.Context,
	signedTxns [][]byte,
	algodClient *algod.Client,
	waitForConfirmation bool,
	w io.Writer,
) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if w == nil {
		w = os.Stdout
	}
	if len(signedTxns) == 0 {
		return nil, fmt.Errorf("no signed transactions to submit")
	}

	_, _ = fmt.Fprintln(w, "\nSubmitting to network...")

	// Compute all transaction IDs before submitting
	var txIDs []string
	for _, signedTxn := range signedTxns {
		var stxn types.SignedTxn
		if err := msgpack.Decode(signedTxn, &stxn); err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction: %w", err)
		}
		txIDs = append(txIDs, crypto.GetTxID(stxn.Txn))
	}

	// For atomic groups, concatenate all signed transactions into a single blob
	// This is required for Algorand to properly validate the group
	what := "transaction"
	blob := signedTxns[0]
	if len(signedTxns) > 1 {
		what = "transaction group"
		blob = bytes.Join(signedTxns, nil)
	}

	// From here a failure is a *SubmissionError naming the IDs and how far
	// the group got, which every caller keeps when it wraps the error.
	if err := ctx.Err(); err != nil {
		return nil, submissionFailure(txIDs, SubmissionNotSent, fmt.Errorf("failed to submit %s: %w", what, err))
	}
	if _, err := algodClient.SendRawTransaction(blob).Do(ctx); err != nil {
		return nil, submissionFailure(txIDs, submitCallState(err), fmt.Errorf("failed to submit %s: %w", what, cleanSubmitError(err)))
	}

	_, _ = fmt.Fprintln(w, "✓ Transaction(s) submitted")
	_, _ = fmt.Fprintln(w, "\nTransaction IDs:")
	for i, txID := range txIDs {
		_, _ = fmt.Fprintf(w, "  %d. %s\n", i+1, txID)
	}

	// Wait for confirmation if requested
	if waitForConfirmation && len(txIDs) > 0 {
		// For atomic groups, waiting on first txID confirms the whole group
		_, _ = fmt.Fprint(w, "\nWaiting for confirmation")
		// Wait up to confirmationTimeoutRounds for the transaction to appear in a block.
		// At ~3.3s/round, 4 rounds ≈ 13 seconds — well above typical confirmation time.
		const confirmationTimeoutRounds = 4
		confirmedTxn, err := transaction.WaitForConfirmation(algodClient, txIDs[0], confirmationTimeoutRounds, ctx)
		if err != nil {
			_, _ = fmt.Fprintln(w)
			return txIDs, submissionFailure(txIDs, SubmissionSubmitted, fmt.Errorf("confirmation failed: %w", err))
		}
		_, _ = fmt.Fprintf(w, "\n✓ Confirmed in round %d\n", confirmedTxn.ConfirmedRound)
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
