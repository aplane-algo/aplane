// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// SubmitOptions bundles optional parameters for SignAndSubmitViaGroup.
type SubmitOptions struct {
	Ctx                 context.Context
	WaitForConfirmation bool
	Verbose             bool
	LsigArgsMap         []map[string][]byte
	AppCallInfo         []*signerapi.AppCallInfo
	Simulate            bool
	// Out is the writer for progress/status output. Defaults to os.Stdout if nil.
	Out io.Writer
	// TxnWriter is called for each original transaction after successful
	// submission or simulation. If nil, no callback is made.
	// Parameters: transaction, transaction ID.
	TxnWriter func(txn types.Transaction, txID string)
}

// SignAndSubmitViaGroup signs transactions using the /sign endpoint, then
// submits or simulates the returned executable group through the client algod.
// This is the simplified flow where the server handles:
// - Dummy transaction creation for LSig budget
// - Fee pooling across LSig transactions
// - Group ID computation
//
// The client only needs to build transactions with suggested params and send them.
// Returns transaction IDs, the submitted transactions, and an error. The submitted
// transactions reflect signer-side planning mutations such as fee pooling, group
// assignment, and appended dummy transactions.
func SignAndSubmitViaGroup(
	txns []types.Transaction,
	authCache *cache.AuthAddressCache,
	signerClient *signerclient.Client,
	algodClient *algod.Client,
	opts SubmitOptions,
) ([]string, []types.Transaction, error) {
	if len(txns) == 0 {
		return nil, nil, fmt.Errorf("no transactions provided")
	}

	if signerClient == nil {
		return nil, nil, fmt.Errorf("not connected to Signer")
	}
	if algodClient == nil {
		return nil, nil, fmt.Errorf("algod client not configured")
	}

	w := opts.Out
	if w == nil {
		w = os.Stdout
	}
	if opts.Ctx == nil {
		opts.Ctx = context.Background()
	}

	// Build sign requests
	requests := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		sender := txn.Sender.String()
		effectiveSigner := authCache.ResolveEffectiveSigner(sender)

		// Convert lsigArgs to hex if present
		var lsigArgsHex map[string]string
		if i < len(opts.LsigArgsMap) && opts.LsigArgsMap[i] != nil {
			lsigArgsHex = make(map[string]string)
			for name, value := range opts.LsigArgsMap[i] {
				lsigArgsHex[name] = hex.EncodeToString(value)
			}
		}

		requests[i] = signerapi.SignRequest{
			AuthAddress: effectiveSigner,
			TxnSender:   sender,
			TxnBytesHex: hex.EncodeToString(txnutil.EncodeWithPrefix(txn)),
			LsigArgs:    lsigArgsHex,
		}
		if i < len(opts.AppCallInfo) {
			requests[i].AppCallInfo = opts.AppCallInfo[i]
		}

		if opts.Verbose {
			_, _ = fmt.Fprintf(w, "  Transaction %d: %s → %s\n", i+1, sender[:8]+"...", FormatTransactionSummary(txn, nil))
		}
	}

	if opts.Verbose {
		if opts.Simulate {
			_, _ = fmt.Fprintf(w, "Requesting executable signatures for client-side simulation of %d transaction(s)...\n", len(txns))
		} else {
			_, _ = fmt.Fprintf(w, "Sending %d transaction(s) to /sign...\n", len(txns))
		}
	}

	// Send to /sign endpoint
	resp, err := signerClient.RequestGroupSignWithContext(opts.Ctx, requests)
	if err != nil {
		return nil, nil, err
	}

	if resp.Mutations != nil && resp.Mutations.ForeignCount > 0 {
		return nil, nil, fmt.Errorf("/sign returned %d foreign placeholder slot(s); use /plan or a list-based multi-party flow instead", resp.Mutations.ForeignCount)
	}

	if err := validateSignedGroupShape(resp.Signed, len(txns)); err != nil {
		return nil, nil, err
	}

	signedTxns, err := decodeSignedTransactionHex(resp.Signed)
	if err != nil {
		return nil, nil, err
	}

	if opts.Verbose {
		dummyCount := len(signedTxns) - len(txns)
		if dummyCount > 0 {
			_, _ = fmt.Fprintf(w, "✓ Signed %d main + %d dummy transaction(s)\n", len(txns), dummyCount)
		} else {
			_, _ = fmt.Fprintf(w, "✓ Signed %d transaction(s)\n", len(txns))
		}
		if m := resp.Mutations; m != nil {
			if m.TotalFeesDelta > 0 {
				_, _ = fmt.Fprintf(w, "  Fee adjustment: +%d µAlgos across group\n", m.TotalFeesDelta)
			}
			if m.PassthroughCount > 0 {
				_, _ = fmt.Fprintf(w, "  Passthrough: %d transaction(s) included as-is\n", m.PassthroughCount)
			}
		}
	}

	signedObjects, submittedTxns, _, err := decodeSignedTransactionObjects(signedTxns)
	if err != nil {
		return nil, nil, err
	}
	if err := validateSignedGroupMutations(txns, signedObjects, signedTxns, resp.Mutations); err != nil {
		return nil, nil, fmt.Errorf("verify signer response: %w", err)
	}
	if opts.Simulate {
		txIDs, simErr := signing.SimulateSignedTransactionsWithContext(opts.Ctx, signedObjects, algodClient, w)
		writeSubmittedTransactions(opts.TxnWriter, submittedTxns, txIDs, len(txns))
		return txIDs, submittedTxns, simErr
	}

	txIDs, err := signing.SubmitTransactionsWithContext(opts.Ctx, signedTxns, algodClient, opts.WaitForConfirmation, w)
	if err != nil {
		return txIDs, submittedTxns, err
	}

	// Invoke TxnWriter callback for each original transaction slot (not dummies).
	// This relies on the server contract that dummies are always appended
	// after the original transactions, so txIDs[0..len(txns)] correspond
	// to submittedTxns[0..len(txns)] positionally.
	writeSubmittedTransactions(opts.TxnWriter, submittedTxns, txIDs, len(txns))

	return txIDs, submittedTxns, nil
}

// validateSignedGroupShape rejects a truncated or partially empty /sign reply
// before submission. This path sends only sign-mode requests (foreign slots are
// rejected above), so every requested position must come back non-empty, and
// the server may append signed dummy transactions after them. An empty hex slot
// would otherwise decode to empty bytes and submit an incomplete group. The
// SDKs apply the same check; this brings the internal client to parity.
func validateSignedGroupShape(signed []string, requestCount int) error {
	if len(signed) < requestCount {
		return fmt.Errorf("signer returned %d signed transaction(s), want at least %d", len(signed), requestCount)
	}
	for i, s := range signed {
		if s == "" {
			return fmt.Errorf("signer returned an empty signed transaction at position %d", i+1)
		}
	}
	return nil
}

func decodeSignedTransactionHex(signedHex []string) ([][]byte, error) {
	signedTxns := make([][]byte, len(signedHex))
	for i, hexStr := range signedHex {
		signedBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
		}
		signedTxns[i] = signedBytes
	}
	return signedTxns, nil
}

func decodeSignedTransactionObjects(signedTxns [][]byte) ([]types.SignedTxn, []types.Transaction, []string, error) {
	signedObjects := make([]types.SignedTxn, len(signedTxns))
	txns := make([]types.Transaction, len(signedTxns))
	txIDs := make([]string, len(signedTxns))
	for i, signedBytes := range signedTxns {
		var signed types.SignedTxn
		if err := msgpack.Decode(signedBytes, &signed); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
		}
		signedObjects[i] = signed
		txns[i] = signed.Txn
		txIDs[i] = sdkcrypto.GetTxID(signed.Txn)
	}
	return signedObjects, txns, txIDs, nil
}

func writeSubmittedTransactions(
	writer func(types.Transaction, string),
	txns []types.Transaction,
	txIDs []string,
	originalCount int,
) {
	if writer == nil {
		return
	}
	if originalCount > len(txns) {
		originalCount = len(txns)
	}
	for i := 0; i < originalCount; i++ {
		if i < len(txIDs) {
			writer(txns[i], txIDs[i])
		}
	}
}
