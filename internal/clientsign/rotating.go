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

	"github.com/aplane-algo/aplane/internal/cache"
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
// The client knows nothing about stages: it sends the transactions and shows
// what the signer reports.
type RotatingOptions struct {
	SubmitOptions
}

// SignAndSubmitRotating runs the rotating1 flow for a group holding one
// transaction from a rotating account, txns[rotating], and any number of
// transactions the signer signs with ordinary keys: prepare, check the
// prepared group, simulate it unsigned, then sign and submit exactly those
// bytes. Nothing is revealed before the sign step, so a failed check or
// simulation costs nothing. In simulate mode it stops after the unsigned
// simulation and never signs.
//
// The other transactions are signed by their effective signers, which
// authCache resolves exactly as on the ordinary path; a nil authCache
// signs each with its sender's own key. Every transaction shares the
// rotating transaction's validity window, capped at what the stage program
// accepts: the client aligns the windows before preparing, since the group
// confirms or fails as a whole and the signer refuses mismatched windows.
//
// The signer releases a signature only while the validity window is current
// (FirstValid at most RotatingMaxLead rounds ahead, at least
// RotatingMinRemaining rounds left). A group prepared earlier, such as a
// later member of a non-atomic batch, may have aged past that by the time
// its turn comes, so each attempt checks the window against the current
// round first and rebuilds every transaction's validity rounds when it has
// aged. If the signer then reports that the account's authorizer moved
// between prepare and sign (rotating_stage_changed), or that the window aged
// while it waited for approval, no signature was released: the group is
// rebuilt with fresh validity rounds, prepared, simulated and presented for
// approval again, a bounded number of times.
func SignAndSubmitRotating(
	txns []types.Transaction,
	rotating int,
	authCache *cache.AuthAddressCache,
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
	if len(txns) == 0 || len(txns) > signerapi.MaxRotatingUserSlots {
		return nil, nil, fmt.Errorf("a rotating group holds 1 to %d transactions, got %d", signerapi.MaxRotatingUserSlots, len(txns))
	}
	if rotating < 0 || rotating >= len(txns) {
		return nil, nil, fmt.Errorf("rotating transaction index %d is outside the group", rotating)
	}
	if opts.Ctx == nil {
		opts.Ctx = context.Background()
	}
	w := opts.Out
	if w == nil {
		w = io.Discard
	}
	work := append([]types.Transaction(nil), txns...)
	for i, txn := range work {
		if txn.Group != (types.Digest{}) {
			return nil, nil, fmt.Errorf("transaction %d: rotating group transactions must be ungrouped; the signer forms the group", i+1)
		}
		if !txn.RekeyTo.IsZero() {
			if i == rotating {
				return nil, nil, fmt.Errorf("rotating account transactions must not set rekey_to; the signer rotates the account itself")
			}
			return nil, nil, fmt.Errorf("transaction %d: transactions grouped with a rotating spend must not set rekey_to", i+1)
		}
	}
	capRotatingWindow(&work[rotating], w, opts.Verbose)
	alignRotatingWindows(work, rotating, w, opts.Verbose)
	slots := rotatingSlotRequests(work, rotating, authCache, opts.SubmitOptions)

	var lastErr error
	for attempt := 1; attempt <= rotatingRetryAttempts; attempt++ {
		fresh, aged, err := freshenRotatingValidity(opts.Ctx, work[rotating], algodClient)
		if err != nil {
			return nil, nil, err
		}
		if aged {
			_, _ = fmt.Fprintf(w, "  Validity window has aged (rounds %d-%d); rebuilding it from the current round\n", work[rotating].FirstValid, work[rotating].LastValid)
			work = withValidity(work, fresh.FirstValid, fresh.LastValid)
		}
		txIDs, prepared, err := signAndSubmitRotatingOnce(work, rotating, slots, signerClient, algodClient, opts, w)
		if err == nil {
			return txIDs, prepared, nil
		}
		if txIDs != nil || !isRotatingRetryable(err) || attempt == rotatingRetryAttempts {
			return txIDs, prepared, err
		}
		lastErr = err
		_, _ = fmt.Fprintf(w, "  Signer refused before signing (%s); rebuilding the transaction with fresh validity rounds (attempt %d of %d)\n", rotatingRefusalSummary(err), attempt+1, rotatingRetryAttempts)
		refreshed, refreshErr := refreshRotatingValidity(opts.Ctx, work[rotating], algodClient)
		if refreshErr != nil {
			return nil, nil, fmt.Errorf("%w (and refreshing validity rounds failed: %v)", err, refreshErr)
		}
		work = withValidity(work, refreshed.FirstValid, refreshed.LastValid)
	}
	return nil, nil, lastErr
}

// rotatingSlotRequests builds each slot's authorization context, the part of
// a sign request that does not change between attempts: the rotating slot
// carries none, since the signer selects its stage, and every other slot
// names its effective signer and its LogicSig arguments exactly as the
// ordinary path does. Every slot, the rotating one included, carries its
// app-call metadata for the approval prompt. The transaction bytes are filled
// in per request.
func rotatingSlotRequests(txns []types.Transaction, rotating int, authCache *cache.AuthAddressCache, opts SubmitOptions) []signerapi.SignRequest {
	slots := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		sender := txn.Sender.String()
		slots[i].TxnSender = sender
		if i < len(opts.AppCallInfo) {
			slots[i].AppCallInfo = opts.AppCallInfo[i]
		}
		if i == rotating {
			continue
		}
		slots[i].AuthAddress = sender
		if authCache != nil {
			slots[i].AuthAddress = authCache.ResolveEffectiveSigner(sender)
		}
		if i < len(opts.LsigArgsMap) && len(opts.LsigArgsMap[i]) > 0 {
			slots[i].LsigArgs = make(map[string]string, len(opts.LsigArgsMap[i]))
			for name, value := range opts.LsigArgsMap[i] {
				slots[i].LsigArgs[name] = hex.EncodeToString(value)
			}
		}
	}
	return slots
}

// withTxnBytes returns the slots' requests carrying txns' bytes.
func withTxnBytes(slots []signerapi.SignRequest, txns []types.Transaction) []signerapi.SignRequest {
	out := make([]signerapi.SignRequest, len(slots))
	for i := range slots {
		out[i] = slots[i]
		out[i].TxnBytesHex = txnutil.EncodeWithPrefixHex(txns[i])
	}
	return out
}

func signAndSubmitRotatingOnce(
	txns []types.Transaction,
	rotating int,
	slots []signerapi.SignRequest,
	signerClient *signerclient.Client,
	algodClient *algod.Client,
	opts RotatingOptions,
	w io.Writer,
) ([]string, []types.Transaction, error) {
	account := txns[rotating].Sender.String()
	prep, err := signerClient.PrepareRotatingWithContext(opts.Ctx, signerapi.RotatingPrepareRequest{
		Account:  account,
		Requests: withTxnBytes(slots, txns),
	})
	if err != nil {
		return nil, nil, err
	}
	prepared, err := ValidatePreparedRotatingGroup(txns, rotating, prep)
	if err != nil {
		return nil, nil, fmt.Errorf("verify prepared rotating group: %w", err)
	}
	rotation := prep.Rotations[0]
	if opts.Verbose {
		_, _ = fmt.Fprintf(w, "  Prepared rotation: stage %d signs and hands the account to stage %d (%s)\n", rotation.Stage, rotation.Target, rotation.RekeyTo)
		if len(txns) > 1 {
			_, _ = fmt.Fprintf(w, "  The signer signs %d other transaction(s) in the group with ordinary keys\n", len(prep.OwnedIndexes))
		}
	}

	// Simulate the exact unsigned group before any keys are revealed.
	simIDs, simErr := signing.SimulateUnsignedTransactionsWithContext(opts.Ctx, prepared, algodClient, w)
	if simErr != nil {
		return nil, nil, fmt.Errorf("prepared group failed simulation; nothing was signed: %w", simErr)
	}
	if opts.Simulate {
		writeSubmittedTransactions(opts.TxnWriter, prepared, simIDs, len(txns))
		return simIDs, prepared, nil
	}

	signed, err := signerClient.SignRotatingWithContext(opts.Ctx, signerapi.RotatingSignRequest{
		Account:  account,
		Requests: withTxnBytes(slots, prepared[:len(txns)]),
	})
	if err != nil {
		return nil, nil, err
	}
	signedBytes, err := validateSignedRotatingGroup(prepared, rotating, signed)
	if err != nil {
		return nil, nil, fmt.Errorf("verify signer response: %w", err)
	}
	released := signed.Rotations[0]
	if opts.Verbose {
		_, _ = fmt.Fprintf(w, "  Signed by stage %d; submit now, its keys are revealed until this transaction or a later rotation confirms\n", released.Stage)
	}
	txIDs, err := signing.SubmitTransactionsWithContext(opts.Ctx, signedBytes, algodClient, opts.WaitForConfirmation, w)
	if err != nil {
		if isAuthorizerMovedRejection(err) {
			return txIDs, prepared, fmt.Errorf("submit rotating spend %s: the account rotated under this transaction (another release from the same stage landed first); prepare again: %w", released.TxID, err)
		}
		return txIDs, prepared, fmt.Errorf("submit rotating spend %s: %w", released.TxID, err)
	}
	writeSubmittedTransactions(opts.TxnWriter, prepared, txIDs, len(txns))
	return txIDs, prepared, nil
}

// alignRotatingWindows gives every transaction the rotating transaction's
// validity rounds. The group confirms or fails as a whole, so a different
// window on another member gains nothing, and the signer refuses a group
// whose windows differ.
func alignRotatingWindows(txns []types.Transaction, rotating int, w io.Writer, verbose bool) {
	first, last := txns[rotating].FirstValid, txns[rotating].LastValid
	for i := range txns {
		if i == rotating || (txns[i].FirstValid == first && txns[i].LastValid == last) {
			continue
		}
		if verbose {
			_, _ = fmt.Fprintf(w, "  Transaction %d validity rounds aligned to the rotating spend's (%d-%d)\n", i+1, first, last)
		}
		txns[i].FirstValid, txns[i].LastValid = first, last
	}
}

// withValidity returns txns with every transaction's validity rounds set to
// first-last.
func withValidity(txns []types.Transaction, first, last types.Round) []types.Transaction {
	out := append([]types.Transaction(nil), txns...)
	for i := range out {
		out[i].FirstValid, out[i].LastValid = first, last
	}
	return out
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

// ValidatePreparedRotatingGroup checks a prepared group against the
// transactions the client sent, txns[rotating] being the rotating account's.
// The signer may set the rotating transaction's RekeyTo to the reported
// next-stage address, raise any transaction's fee when it reports the
// change, assign the group ID, and append canonical resource dummies after
// the transactions sent, in the order sent. The reported stage and target
// must be consecutive. The client cannot derive stage addresses, so the
// signer's own validation at sign time, which derives the target from the
// seed, is what pins the target; this check keeps the signer honest about
// the rest. It is also where the client's intent is preserved: the signer's
// own rebuild proves only that a group is one it would build.
func ValidatePreparedRotatingGroup(original []types.Transaction, rotating int, prep *signerapi.RotatingPrepareResponse) ([]types.Transaction, error) {
	if prep == nil {
		return nil, fmt.Errorf("empty prepare response")
	}
	if rotating < 0 || rotating >= len(original) {
		return nil, fmt.Errorf("rotating transaction index %d is outside the group", rotating)
	}
	if prep.Account != original[rotating].Sender.String() {
		return nil, fmt.Errorf("prepared account %s is not the sender", prep.Account)
	}
	if len(prep.Rotations) != 1 {
		return nil, fmt.Errorf("prepared group reports %d rotations, want 1", len(prep.Rotations))
	}
	rotation := prep.Rotations[0]
	if rotation.Index != rotating {
		return nil, fmt.Errorf("prepared rotation is at transaction %d, the rotating account's transaction is %d", rotation.Index+1, rotating+1)
	}
	if rotation.Target != rotation.Stage+1 {
		return nil, fmt.Errorf("prepared target stage %d is not the stage after %d", rotation.Target, rotation.Stage)
	}
	if prep.Stage != rotation.Stage || prep.Target != rotation.Target || prep.RekeyTo != rotation.RekeyTo {
		return nil, fmt.Errorf("prepared stage, target and rekey_to do not match the reported rotation")
	}
	wantOwned := make([]int, 0, len(original)-1)
	for i := range original {
		if i != rotating {
			wantOwned = append(wantOwned, i)
		}
	}
	if !equalIndices(prep.OwnedIndexes, wantOwned) {
		return nil, fmt.Errorf("prepared owned_indexes %v, want %v", prep.OwnedIndexes, wantOwned)
	}
	rekeyTo, err := types.DecodeAddress(rotation.RekeyTo)
	if err != nil {
		return nil, fmt.Errorf("invalid rekey_to: %w", err)
	}
	if rekeyTo.IsZero() || rekeyTo == original[rotating].Sender {
		return nil, fmt.Errorf("rekey_to must be another, non-zero address")
	}
	group, err := canonical.DecodeGroupHex(prep.Transactions)
	if err != nil {
		return nil, err
	}
	if len(group.Entries) < len(original) {
		return nil, fmt.Errorf("prepared group has %d transactions, fewer than the %d sent", len(group.Entries), len(original))
	}
	txns := make([]types.Transaction, len(group.Entries))
	for i, e := range group.Entries {
		txns[i] = e.Txn
	}
	feeReported, err := reportedFeeIndices(prep.Mutations, len(original), len(txns))
	if err != nil {
		return nil, err
	}
	var feeDelta uint64
	for i := range original {
		got := txns[i]
		expected := original[i]
		expected.Group = group.GroupID
		if i == rotating {
			expected.RekeyTo = rekeyTo
		}
		switch {
		case got.Fee < expected.Fee:
			return nil, fmt.Errorf("signer lowered the fee of transaction %d", i+1)
		case got.Fee > expected.Fee:
			if !feeReported[i] {
				return nil, fmt.Errorf("signer raised the fee of transaction %d without reporting it", i+1)
			}
			feeDelta += uint64(got.Fee - expected.Fee)
			expected.Fee = got.Fee
		case feeReported[i]:
			return nil, fmt.Errorf("signer reported a fee change on transaction %d that did not raise its fee", i+1)
		}
		if !bytes.Equal(txnutil.EncodeWithPrefix(expected), group.Entries[i].Raw) {
			if i == rotating {
				return nil, fmt.Errorf("signer changed fields other than rekey_to, fee and group on the rotating transaction")
			}
			return nil, fmt.Errorf("signer changed fields other than fee and group on transaction %d", i+1)
		}
	}
	if prep.Mutations != nil && uint64(prep.Mutations.TotalFeesDelta) != feeDelta {
		return nil, fmt.Errorf("mutation total_fees_delta %d does not match observed delta %d", prep.Mutations.TotalFeesDelta, feeDelta)
	}
	if len(txns) > len(original) {
		if _, err := ValidateCanonicalDummyTxns(original[0], group.GroupID, txns[len(original):]); err != nil {
			return nil, err
		}
	}
	return txns, nil
}

// reportedFeeIndices checks a prepare response's mutation report against
// the group's shape and returns the positions it reports a fee change on.
func reportedFeeIndices(m *signerapi.MutationReport, sent, final int) (map[int]bool, error) {
	reported := map[int]bool{}
	if m == nil {
		if final != sent {
			return nil, fmt.Errorf("signer appended %d transaction(s) without a mutation report", final-sent)
		}
		return reported, nil
	}
	switch {
	case m.OriginalCount != sent:
		return nil, fmt.Errorf("mutation original_count %d does not match the %d transactions sent", m.OriginalCount, sent)
	case m.FinalCount != final:
		return nil, fmt.Errorf("mutation final_count %d does not match the %d transactions returned", m.FinalCount, final)
	case m.DummiesAdded != final-sent:
		return nil, fmt.Errorf("mutation dummies_added %d does not match the %d appended", m.DummiesAdded, final-sent)
	case m.PassthroughCount != 0 || m.ForeignCount != 0:
		return nil, fmt.Errorf("a rotating group reported passthrough or foreign transactions")
	case m.TotalFeesDelta < 0:
		return nil, fmt.Errorf("mutation total_fees_delta must not be negative")
	}
	for _, index := range m.FeesModified {
		if index < 0 || index >= sent {
			return nil, fmt.Errorf("mutation fee index %d is outside the transactions sent", index)
		}
		if reported[index] {
			return nil, fmt.Errorf("mutation fee index %d is duplicated", index)
		}
		reported[index] = true
	}
	return reported, nil
}

func equalIndices(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// validateSignedRotatingGroup checks that the signer signed exactly the
// prepared bytes, dummies included, and reported the rotation where the
// client put it, and returns the encoded signed transactions. Each element
// must be one canonically encoded signed transaction: the bytes go to the
// node as returned, so trailing bytes, which the node would read as a
// further transaction, are rejected.
func validateSignedRotatingGroup(prepared []types.Transaction, rotating int, resp *signerapi.RotatingSignResponse) ([][]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("empty sign response")
	}
	if len(resp.Rotations) != 1 || resp.Rotations[0].Index != rotating {
		return nil, fmt.Errorf("signed group does not report the rotation at transaction %d", rotating+1)
	}
	if r := resp.Rotations[0]; r.Stage != resp.Stage || r.Target != resp.Target || r.TxID != resp.TxID {
		return nil, fmt.Errorf("signed stage, target and txid do not match the reported rotation")
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
