// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// rotatingRetryAttempts bounds how many times a rotating spend is rebuilt
// after the signer reports that the account moved or the window aged.
const rotatingRetryAttempts = 3

// RotatingOptions are the submit options of a rotating account transaction.
// The client knows nothing about stages: it sends the transaction and shows
// what the signer reports.
type RotatingOptions struct {
	SubmitOptions
}

// SignAndSubmitRotating runs the rotating1 flow for one transaction from a
// rotating account: prepare, check the prepared group, simulate it unsigned,
// then sign and submit exactly those bytes. Nothing is revealed before the
// sign step, so a failed check or simulation costs nothing. In simulate mode
// it stops after the unsigned simulation and never signs.
//
// The signer releases a signature only while the validity window is current
// (FirstValid at most RotatingMaxLead rounds ahead, at least
// RotatingMinRemaining rounds left). A transaction prepared earlier, such as
// a later member of a non-atomic batch, may have aged past that by the time
// its turn comes, so each attempt checks the window against the current
// round first and rebuilds the validity rounds when it has aged. If the
// signer then reports that the account's authorizer moved between prepare
// and sign (rotating_stage_changed), or that the window aged while it
// waited for approval, nothing was signed: the transaction is rebuilt with
// fresh validity rounds, prepared, simulated and presented for approval
// again, a bounded number of times.
func SignAndSubmitRotating(
	txn types.Transaction,
	signerClient *signerclient.Client,
	algodClient *algod.Client,
	opts RotatingOptions,
) ([]string, []types.Transaction, error) {
	if signerClient == nil {
		return nil, nil, fmt.Errorf("not connected to Signer")
	}
	if algodClient == nil {
		return nil, nil, fmt.Errorf("algod client not configured")
	}
	if opts.Ctx == nil {
		opts.Ctx = context.Background()
	}
	w := opts.Out
	if w == nil {
		w = io.Discard
	}
	if txn.Group != (types.Digest{}) {
		return nil, nil, fmt.Errorf("rotating account transactions must be ungrouped; the signer forms the group")
	}
	if !txn.RekeyTo.IsZero() {
		return nil, nil, fmt.Errorf("rotating account transactions must not set rekey_to; the signer rotates the account itself")
	}
	capRotatingWindow(&txn, w, opts.Verbose)

	var lastErr error
	for attempt := 1; attempt <= rotatingRetryAttempts; attempt++ {
		fresh, aged, err := freshenRotatingValidity(opts.Ctx, txn, algodClient)
		if err != nil {
			return nil, nil, err
		}
		if aged {
			_, _ = fmt.Fprintf(w, "  Validity window has aged (rounds %d-%d); rebuilding it from the current round\n", txn.FirstValid, txn.LastValid)
		}
		txn = fresh
		txIDs, prepared, err := signAndSubmitRotatingOnce(txn, signerClient, algodClient, opts, w)
		if err == nil {
			return txIDs, prepared, nil
		}
		if txIDs != nil || !isRotatingRetryable(err) || attempt == rotatingRetryAttempts {
			return txIDs, prepared, err
		}
		lastErr = err
		_, _ = fmt.Fprintf(w, "  Signer refused before signing (%s); rebuilding the transaction with fresh validity rounds (attempt %d of %d)\n", rotatingRefusalSummary(err), attempt+1, rotatingRetryAttempts)
		refreshed, refreshErr := refreshRotatingValidity(opts.Ctx, txn, algodClient)
		if refreshErr != nil {
			return nil, nil, fmt.Errorf("%w (and refreshing validity rounds failed: %v)", err, refreshErr)
		}
		txn = refreshed
	}
	return nil, nil, lastErr
}

func signAndSubmitRotatingOnce(
	txn types.Transaction,
	signerClient *signerclient.Client,
	algodClient *algod.Client,
	opts RotatingOptions,
	w io.Writer,
) ([]string, []types.Transaction, error) {
	account := txn.Sender.String()
	prep, err := signerClient.PrepareRotatingWithContext(opts.Ctx, signerapi.RotatingPrepareRequest{
		Account:     account,
		TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	})
	if err != nil {
		return nil, nil, err
	}
	prepared, err := ValidatePreparedRotatingGroup(txn, prep)
	if err != nil {
		return nil, nil, fmt.Errorf("verify prepared rotating group: %w", err)
	}
	if opts.Verbose {
		_, _ = fmt.Fprintf(w, "  Prepared rotation: stage %d signs and hands the account to stage %d (%s)\n", prep.Stage, prep.Target, prep.RekeyTo)
	}

	// Simulate the exact unsigned group before any keys are revealed.
	simIDs, simErr := signing.SimulateUnsignedTransactionsWithContext(opts.Ctx, prepared, algodClient, w)
	if simErr != nil {
		return nil, nil, fmt.Errorf("prepared group failed simulation; nothing was signed: %w", simErr)
	}
	if opts.Simulate {
		writeSubmittedTransactions(opts.TxnWriter, prepared, simIDs, 1)
		return simIDs, prepared, nil
	}

	signed, err := signerClient.SignRotatingWithContext(opts.Ctx, rotatingSignRequest(account, prep, opts.SubmitOptions))
	if err != nil {
		return nil, nil, err
	}
	signedBytes, err := validateSignedRotatingGroup(prepared, signed)
	if err != nil {
		return nil, nil, fmt.Errorf("verify signer response: %w", err)
	}
	if opts.Verbose {
		_, _ = fmt.Fprintf(w, "  Signed by stage %d; submit now, its keys are revealed until this transaction or a later rotation confirms\n", signed.Stage)
	}
	txIDs, err := signing.SubmitTransactionsWithContext(opts.Ctx, signedBytes, algodClient, opts.WaitForConfirmation, w)
	if err != nil {
		if isAuthorizerMovedRejection(err) {
			return txIDs, prepared, fmt.Errorf("submit rotating spend %s: the account rotated under this transaction (another release from the same stage landed first); prepare again: %w", signed.TxID, err)
		}
		return txIDs, prepared, fmt.Errorf("submit rotating spend %s: %w", signed.TxID, err)
	}
	writeSubmittedTransactions(opts.TxnWriter, prepared, txIDs, 1)
	return txIDs, prepared, nil
}

// capRotatingWindow shortens the validity window to what the stage program
// accepts.
func capRotatingWindow(txn *types.Transaction, w io.Writer, verbose bool) {
	if txn.LastValid > txn.FirstValid+rotatingkey.RotatingMaxValidityWindow {
		txn.LastValid = txn.FirstValid + rotatingkey.RotatingMaxValidityWindow
		if verbose {
			_, _ = fmt.Fprintf(w, "  Validity window shortened to %d rounds for the rotating account\n", rotatingkey.RotatingMaxValidityWindow)
		}
	}
}

// freshenRotatingValidity reads the current round and reports whether the
// transaction's validity window would fail the signer's timing rule. An
// aged transaction comes back with validity rounds rebuilt from current
// suggested parameters; a current one comes back unchanged.
func freshenRotatingValidity(ctx context.Context, txn types.Transaction, algodClient *algod.Client) (types.Transaction, bool, error) {
	status, err := algodClient.Status().Do(ctx)
	if err != nil {
		return txn, false, fmt.Errorf("read current round: %w", err)
	}
	round := status.LastRound
	if uint64(txn.FirstValid) <= round+rotatingkey.RotatingMaxLead && uint64(txn.LastValid) >= round+rotatingkey.RotatingMinRemaining {
		return txn, false, nil
	}
	fresh, err := refreshRotatingValidity(ctx, txn, algodClient)
	if err != nil {
		return txn, true, err
	}
	return fresh, true, nil
}

// refreshRotatingValidity rebuilds the transaction's validity rounds from
// current suggested parameters, keeping everything else.
func refreshRotatingValidity(ctx context.Context, txn types.Transaction, algodClient *algod.Client) (types.Transaction, error) {
	sp, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return txn, fmt.Errorf("fetch suggested params: %w", err)
	}
	window := txn.LastValid - txn.FirstValid
	if window > rotatingkey.RotatingMaxValidityWindow || window == 0 {
		window = rotatingkey.RotatingMaxValidityWindow
	}
	txn.FirstValid = sp.FirstRoundValid
	txn.LastValid = sp.FirstRoundValid + window
	return txn, nil
}

// isRotatingRetryable reports whether a signer refusal means nothing was
// signed and a rebuilt transaction may succeed: the account moved between
// prepare and sign, or the validity window aged past the signer's bounds.
func isRotatingRetryable(err error) bool {
	var httpErr *signerclient.HTTPStatusError
	if !errors.As(err, &httpErr) {
		return false
	}
	switch httpErr.Code {
	case signerapi.ErrCodeRotatingStageChanged:
		return true
	case signerapi.ErrCodeBadRequest:
		msg := httpErr.Message
		return strings.Contains(msg, "ahead of the current round") || strings.Contains(msg, "remain before last valid")
	}
	return false
}

func rotatingRefusalSummary(err error) string {
	var httpErr *signerclient.HTTPStatusError
	if errors.As(err, &httpErr) {
		if httpErr.Code == signerapi.ErrCodeRotatingStageChanged {
			return "the account's authorizer moved"
		}
		return "the validity window aged"
	}
	return err.Error()
}

// isAuthorizerMovedRejection recognises the ledger's rejection of a
// transaction whose authorizer is no longer the account's.
func isAuthorizerMovedRejection(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "should have been authorized by")
}

// rotatingSignRequest is the sign request for a prepared spend: the prepared
// group exactly as returned, and the spend's app-call metadata, which the
// signer uses only to render the approval prompt.
func rotatingSignRequest(account string, prep *signerapi.RotatingPrepareResponse, opts SubmitOptions) signerapi.RotatingSignRequest {
	req := signerapi.RotatingSignRequest{Account: account, Transactions: prep.Transactions}
	if len(opts.AppCallInfo) > 0 {
		req.AppCallInfo = opts.AppCallInfo[0]
	}
	return req
}

// ValidatePreparedRotatingGroup checks a prepared group against the
// transaction the client sent. The signer may only set RekeyTo to the
// reported next-stage address, raise the spend's fee, assign the group ID,
// and append canonical resource dummies. The reported stage and target must
// be consecutive. The client cannot derive stage addresses, so the signer's
// own validation at sign time, which derives the target from the seed, is
// what pins the target; this check keeps the signer honest about the rest.
func ValidatePreparedRotatingGroup(original types.Transaction, prep *signerapi.RotatingPrepareResponse) ([]types.Transaction, error) {
	if prep == nil {
		return nil, fmt.Errorf("empty prepare response")
	}
	if prep.Account != original.Sender.String() {
		return nil, fmt.Errorf("prepared account %s is not the sender", prep.Account)
	}
	if prep.Target != prep.Stage+1 {
		return nil, fmt.Errorf("prepared target stage %d is not the stage after %d", prep.Target, prep.Stage)
	}
	group, err := canonical.DecodeGroupHex(prep.Transactions)
	if err != nil {
		return nil, err
	}
	raws := make([][]byte, len(group.Entries))
	txns := make([]types.Transaction, len(group.Entries))
	for i, e := range group.Entries {
		raws[i], txns[i] = e.Raw, e.Txn
	}
	rekeyTo, err := types.DecodeAddress(prep.RekeyTo)
	if err != nil {
		return nil, fmt.Errorf("invalid rekey_to: %w", err)
	}
	if rekeyTo.IsZero() || rekeyTo == original.Sender {
		return nil, fmt.Errorf("rekey_to must be another, non-zero address")
	}
	spend := txns[0]
	if spend.Fee < original.Fee {
		return nil, fmt.Errorf("signer lowered the fee")
	}
	expected := original
	expected.RekeyTo = rekeyTo
	expected.Fee = spend.Fee
	expected.Group = group.GroupID
	if !bytes.Equal(txnutil.EncodeWithPrefix(expected), raws[0]) {
		return nil, fmt.Errorf("signer changed fields other than rekey_to, fee and group")
	}
	if len(txns) > 1 {
		params := types.SuggestedParams{
			Fee:             original.Fee,
			FirstRoundValid: original.FirstValid,
			LastRoundValid:  original.LastValid,
			GenesisID:       original.GenesisID,
			GenesisHash:     original.GenesisHash[:],
			FlatFee:         true,
		}
		dummies, err := signing.CreateDummyTransactions(len(txns)-1, params)
		if err != nil {
			return nil, fmt.Errorf("recreate canonical resource dummies: %w", err)
		}
		for i := range dummies {
			dummies[i].Group = group.GroupID
			if !bytes.Equal(txnutil.EncodeWithPrefix(dummies[i]), raws[i+1]) {
				return nil, fmt.Errorf("appended transaction %d is not the canonical resource dummy", i+1)
			}
		}
	}
	return txns, nil
}

// validateSignedRotatingGroup checks that the signer signed exactly the
// prepared bytes and returns the encoded signed transactions. Each element
// must be one canonically encoded signed transaction: the bytes go to the
// node as returned, so trailing bytes, which the node would read as a
// further transaction, are rejected.
func validateSignedRotatingGroup(prepared []types.Transaction, resp *signerapi.RotatingSignResponse) ([][]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("empty sign response")
	}
	if len(resp.Signed) != len(prepared) {
		return nil, fmt.Errorf("signed group has %d transactions, prepared %d", len(resp.Signed), len(prepared))
	}
	out := make([][]byte, len(resp.Signed))
	for i, h := range resp.Signed {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: invalid hex: %w", i+1, err)
		}
		var stxn types.SignedTxn
		if err := msgpack.Decode(raw, &stxn); err != nil {
			return nil, fmt.Errorf("transaction %d: %w", i+1, err)
		}
		if !bytes.Equal(msgpack.Encode(stxn), raw) {
			return nil, fmt.Errorf("transaction %d is not a single canonically encoded signed transaction", i+1)
		}
		if !bytes.Equal(txnutil.EncodeWithPrefix(stxn.Txn), txnutil.EncodeWithPrefix(prepared[i])) {
			return nil, fmt.Errorf("transaction %d differs from the prepared transaction", i+1)
		}
		out[i] = raw
	}
	return out, nil
}
