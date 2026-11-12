// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
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
// round first and rebuilds the validity rounds when it is not current; a
// rebuilt window keeps its width unless that is too narrow ever to be
// signed (fewer than RotatingMinRemaining rounds). If the signer then
// refuses, no signature was released, and the transaction is prepared,
// simulated and presented for approval again, a bounded number of times, as
// the SDK does. When the account's authorizer moved between prepare and sign
// (rotating_stage_changed), the same transaction is prepared again; its
// window is rebuilt only if it is no longer current. When the window was not
// current at the round the signer read, for example because it aged during
// approval (rotating_window_not_current), it is rebuilt from the current
// round at the maximum width, since the same width would leave the operator
// no more time.
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
	capRotatingWindow(&txn, w)

	var lastErr error
	// The fee notice last shown: a retry that prepares the same raise again
	// does not repeat it.
	var feeNotice string
	for attempt := 1; attempt <= rotatingRetryAttempts; attempt++ {
		fresh, note, err := freshenRotatingValidity(opts.Ctx, txn, algodClient)
		if err != nil {
			return nil, nil, err
		}
		if note != "" {
			_, _ = fmt.Fprintf(w, "  %s\n", note)
		}
		txn = fresh
		txIDs, prepared, err := signAndSubmitRotatingOnce(txn, signerClient, algodClient, opts, w, &feeNotice)
		if err == nil {
			return txIDs, prepared, nil
		}
		if txIDs != nil || !isRotatingRetryable(err) || attempt == rotatingRetryAttempts {
			return txIDs, prepared, err
		}
		lastErr = err
		if !hasRotatingRefusalCode(err, signerapi.ErrCodeRotatingWindowNotCurrent) {
			_, _ = fmt.Fprintf(w, "  Signer refused and released no signature (%s); preparing the transaction again (attempt %d of %d)\n", rotatingRefusalSummary(err), attempt+1, rotatingRetryAttempts)
			continue
		}
		widened, widenErr := refreshRotatingValidity(opts.Ctx, txn, algodClient, true)
		if widenErr != nil {
			return nil, nil, fmt.Errorf("%w (and rebuilding the validity window failed: %v)", err, widenErr)
		}
		rebuilt := "widened it to"
		if txn.LastValid >= txn.FirstValid && txn.LastValid-txn.FirstValid >= rotatingkey.RotatingMaxValidityWindow {
			rebuilt = "rebuilt it at"
		}
		_, _ = fmt.Fprintf(w, "  Signer found the validity window (rounds %d-%d) no longer current and released no signature; %s the maximum %d rounds from the current round (rounds %d-%d) (attempt %d of %d)\n",
			txn.FirstValid, txn.LastValid, rebuilt, rotatingkey.RotatingMaxValidityWindow, widened.FirstValid, widened.LastValid, attempt+1, rotatingRetryAttempts)
		txn = widened
	}
	return nil, nil, lastErr
}

func signAndSubmitRotatingOnce(
	txn types.Transaction,
	signerClient *signerclient.Client,
	algodClient *algod.Client,
	opts RotatingOptions,
	w io.Writer,
	feeNotice *string,
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
	// The report was checked against the prepared bytes above, so the raise
	// shown is the one the spend pays. It is shown whether or not verbose is
	// set, since the fee comes out of the account's balance, and once per
	// send: a retry shows it again only if the raise changed.
	if m := prep.Mutations; m != nil && m.TotalFeesDelta > 0 {
		notice := fmt.Sprintf("  Signer raised the spend's fee by %d microAlgos for authorization (fee now %d microAlgos)\n", m.TotalFeesDelta, prepared[0].Fee)
		if notice != *feeNotice {
			_, _ = io.WriteString(w, notice)
			*feeNotice = notice
		}
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
	signedBytes, err := validateSignedRotatingGroup(prep, prepared, signed)
	if err != nil {
		return nil, nil, fmt.Errorf("verify signer response: %w", err)
	}
	// The stage and transaction ID below are the prepared ones: the response's
	// echoes of them were checked above.
	if opts.Verbose {
		_, _ = fmt.Fprintf(w, "  Signed by stage %d; submit now, its keys are revealed until this transaction or a later rotation confirms\n", prep.Stage)
	}
	txIDs, err := signing.SubmitTransactionsWithContext(opts.Ctx, signedBytes, algodClient, opts.WaitForConfirmation, w)
	if err != nil {
		if isAuthorizerMovedRejection(err) {
			return txIDs, prepared, fmt.Errorf("submit rotating spend %s: %s: %w", signed.TxID, authorizerMovedSummary(err, prepared[0].RekeyTo), err)
		}
		return txIDs, prepared, fmt.Errorf("submit rotating spend %s: %w", signed.TxID, err)
	}
	writeSubmittedTransactions(opts.TxnWriter, prepared, txIDs, 1)
	return txIDs, prepared, nil
}

// capRotatingWindow shortens the validity window to what the stage program
// accepts, and says so: it changes the transaction the caller built.
func capRotatingWindow(txn *types.Transaction, w io.Writer) {
	if txn.LastValid > txn.FirstValid+rotatingkey.RotatingMaxValidityWindow {
		txn.LastValid = txn.FirstValid + rotatingkey.RotatingMaxValidityWindow
		_, _ = fmt.Fprintf(w, "  Validity window shortened to %d rounds for the rotating account\n", rotatingkey.RotatingMaxValidityWindow)
	}
}

// freshenRotatingValidity reads the current round and checks the
// transaction's validity window against the signer's timing rule. A window
// that fails it comes back rebuilt from current suggested parameters, with a
// note saying why: it is too narrow ever to be signed, it starts too far
// ahead of the current round, or too few of its rounds remain. A current one
// comes back unchanged, with no note.
func freshenRotatingValidity(ctx context.Context, txn types.Transaction, algodClient *algod.Client) (types.Transaction, string, error) {
	status, err := algodClient.Status().Do(ctx)
	if err != nil {
		return txn, "", fmt.Errorf("read current round: %w", err)
	}
	round := status.LastRound
	if uint64(txn.FirstValid) <= round+rotatingkey.RotatingMaxLead && uint64(txn.LastValid) >= round+rotatingkey.RotatingMinRemaining {
		return txn, "", nil
	}
	var note string
	switch {
	case txn.LastValid >= txn.FirstValid && uint64(txn.LastValid-txn.FirstValid) < rotatingkey.RotatingMinRemaining:
		note = fmt.Sprintf("Validity window (rounds %d-%d) spans %d rounds, fewer than the %d a rotating account needs left when it signs; rebuilding it from the current round with %d rounds",
			txn.FirstValid, txn.LastValid, uint64(txn.LastValid-txn.FirstValid), rotatingkey.RotatingMinRemaining, rotatingRebuildWindow(txn))
	case uint64(txn.FirstValid) > round+rotatingkey.RotatingMaxLead:
		note = fmt.Sprintf("Validity window (rounds %d-%d) starts %d rounds ahead of the current round %d, more than the %d a rotating account signs; rebuilding it from the current round",
			txn.FirstValid, txn.LastValid, uint64(txn.FirstValid)-round, round, rotatingkey.RotatingMaxLead)
	default:
		note = fmt.Sprintf("Validity window has aged (rounds %d-%d); rebuilding it from the current round", txn.FirstValid, txn.LastValid)
	}
	fresh, err := refreshRotatingValidity(ctx, txn, algodClient, false)
	if err != nil {
		return txn, note, err
	}
	return fresh, note, nil
}

// rotatingRebuildWindow is the width a rebuilt validity window gets: the
// transaction's own, unless that is over the rotating limit or narrower than
// the rounds that must remain when the signer signs, which could never be
// signed; either of those gets the longest window. The SDK's refresh keeps
// the same rule.
func rotatingRebuildWindow(txn types.Transaction) types.Round {
	if txn.LastValid >= txn.FirstValid {
		if window := txn.LastValid - txn.FirstValid; window >= rotatingkey.RotatingMinRemaining && window <= rotatingkey.RotatingMaxValidityWindow {
			return window
		}
	}
	return rotatingkey.RotatingMaxValidityWindow
}

// refreshRotatingValidity rebuilds the transaction's validity rounds from
// current suggested parameters, keeping everything else. The window gets the
// width rotatingRebuildWindow gives, or with widen the maximum: after the
// signer found the window not current, the same width would leave the
// operator no more time. This is the SDK's refresh rule.
func refreshRotatingValidity(ctx context.Context, txn types.Transaction, algodClient *algod.Client, widen bool) (types.Transaction, error) {
	sp, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return txn, fmt.Errorf("fetch suggested params: %w", err)
	}
	window := types.Round(rotatingkey.RotatingMaxValidityWindow)
	if !widen {
		window = rotatingRebuildWindow(txn)
	}
	if sp.FirstRoundValid > math.MaxUint64-window {
		return txn, fmt.Errorf("first valid round %d leaves no room for a validity window", sp.FirstRoundValid)
	}
	txn.FirstValid = sp.FirstRoundValid
	txn.LastValid = sp.FirstRoundValid + window
	return txn, nil
}

// hasRotatingRefusalCode reports whether err is a signer refusal with the
// given stable code.
func hasRotatingRefusalCode(err error, code string) bool {
	var httpErr *signerclient.HTTPStatusError
	return errors.As(err, &httpErr) && httpErr.Code == code
}

// isRotatingRetryable reports whether a signer refusal released no signature
// and a rebuilt transaction may succeed: the account moved between prepare
// and sign (rotating_stage_changed), or the validity window was not current
// at the round the signer read (rotating_window_not_current). It goes by the
// error code alone, never the message.
func isRotatingRetryable(err error) bool {
	var httpErr *signerclient.HTTPStatusError
	if !errors.As(err, &httpErr) {
		return false
	}
	switch httpErr.Code {
	case signerapi.ErrCodeRotatingStageChanged, signerapi.ErrCodeRotatingWindowNotCurrent:
		return true
	}
	return false
}

func rotatingRefusalSummary(err error) string {
	var httpErr *signerclient.HTTPStatusError
	if errors.As(err, &httpErr) {
		switch httpErr.Code {
		case signerapi.ErrCodeRotatingStageChanged:
			return "the account's authorizer moved"
		case signerapi.ErrCodeRotatingWindowNotCurrent:
			return "the validity window is not current"
		}
	}
	return err.Error()
}

// ledgerAuthorizerRejection is how the ledger starts its rejection of a
// transaction whose authorizer is not the account's, before naming the
// authorizer it expected. It is matched without regard to case.
const ledgerAuthorizerRejection = "should have been authorized by "

// ledgerAuthorizerRejectionRest returns what follows ledgerAuthorizerRejection
// in err, lower-cased, when err is the ledger's rejection of a transaction's
// authorizer.
func ledgerAuthorizerRejectionRest(err error) (string, bool) {
	msg := strings.ToLower(err.Error())
	i := strings.Index(msg, ledgerAuthorizerRejection)
	if i < 0 {
		return "", false
	}
	return msg[i+len(ledgerAuthorizerRejection):], true
}

// isAuthorizerMovedRejection recognises the ledger's rejection of a
// transaction whose authorizer is no longer the account's.
func isAuthorizerMovedRejection(err error) bool {
	_, ok := ledgerAuthorizerRejectionRest(err)
	return ok
}

// ledgerExpectedAuthorizer reads the authorizer the ledger expected from its
// rejection of a transaction's authorizer.
func ledgerExpectedAuthorizer(err error) (types.Address, bool) {
	rest, ok := ledgerAuthorizerRejectionRest(err)
	if !ok {
		return types.Address{}, false
	}
	if end := strings.IndexByte(rest, ' '); end >= 0 {
		rest = rest[:end]
	}
	// Addresses are upper-case base32; the match above lower-cased it.
	addr, decodeErr := types.DecodeAddress(strings.ToUpper(rest))
	if decodeErr != nil {
		return types.Address{}, false
	}
	return addr, true
}

// authorizerMovedSummary says why the ledger refused a signed rotating spend's
// authorizer, and what to do. Every release from a stage hands the account to
// the same next stage, so only when the ledger expects the spend's own rekey
// target did another release from the stage that signed land first, and
// preparing again, from the stage the account is now at, is the remedy. Any
// other expected authorizer is reported as it is, with no advice: the client
// cannot derive stage addresses, so it cannot tell a later rotation from a
// signature by the wrong stage or an account rekeyed elsewhere.
func authorizerMovedSummary(err error, rekeyTo types.Address) string {
	expected, ok := ledgerExpectedAuthorizer(err)
	switch {
	case ok && expected == rekeyTo:
		return "the account rotated under this transaction (another release from the same stage landed first); prepare again"
	case ok:
		return fmt.Sprintf("the ledger expects the account's authorizer to be %s, not the stage program that signed this spend", expected)
	}
	return "the ledger refused the stage program that signed this spend as the account's authorizer"
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
// transaction the client sent and the signer's mutation report. The signer
// may only set RekeyTo to the reported next-stage address, raise the spend's
// fee by what the report says, assign the group ID it reports, and append the
// canonical resource dummies it counts; a report that disagrees with the
// bytes is refused like any other change. The reported stage and target must
// be consecutive. The client cannot derive stage addresses, so the signer's
// own validation at sign time, which derives the target from the seed, is
// what pins the target; this check keeps the signer honest about the rest.
// The checks run in order: the response's own fields, the report's counts,
// the spend's fee and fields, then the dummies.
func ValidatePreparedRotatingGroup(original types.Transaction, prep *signerapi.RotatingPrepareResponse) ([]types.Transaction, error) {
	if prep == nil {
		return nil, fmt.Errorf("empty prepare response")
	}
	if prep.Account != original.Sender.String() {
		return nil, fmt.Errorf("prepared account %s is not the sender", prep.Account)
	}
	// The last stage has no successor, and Stage+1 would wrap to stage 0.
	if prep.Stage == math.MaxUint64 || prep.Target != prep.Stage+1 {
		return nil, fmt.Errorf("prepared target stage %d is not the stage after %d", prep.Target, prep.Stage)
	}
	// DecodeGroupHex admits only canonical encodings and a group ID computed
	// over the group itself.
	group, err := canonical.DecodeGroupHex(prep.Transactions)
	if err != nil {
		return nil, err
	}
	txns := make([]types.Transaction, len(group.Entries))
	for i, e := range group.Entries {
		txns[i] = e.Txn
	}
	rekeyTo, err := types.DecodeAddress(prep.RekeyTo)
	if err != nil {
		return nil, fmt.Errorf("invalid rekey_to: %w", err)
	}
	if rekeyTo.IsZero() || rekeyTo == original.Sender {
		return nil, fmt.Errorf("rekey_to must be another, non-zero address")
	}
	if err := validateMutationReportCounts("rotating prepare", 1, len(txns), prep.Mutations); err != nil {
		return nil, err
	}
	if txns[0].Fee < original.Fee {
		return nil, fmt.Errorf("signer lowered the fee")
	}
	// The rekey is the one change the report does not describe, so it is
	// applied to the expectation; every other difference must be reported.
	expected := original
	expected.RekeyTo = rekeyTo
	if err := ValidateOriginalPositions([]types.Transaction{expected}, txns, prep.Mutations); err != nil {
		return nil, err
	}
	if _, err := ValidateCanonicalDummyTxns(original, group.GroupID, txns, 1); err != nil {
		return nil, err
	}
	return txns, nil
}

// validateSignedRotatingGroup checks the signer's answer against the prepared
// group and returns the encoded signed transactions. Each element must be one
// canonically encoded signed transaction: the bytes go to the node as
// returned, so trailing bytes, which the node would read as a further
// transaction, are rejected. The signer must report the prepared stage and
// target, sign exactly the prepared transactions, authorize the spend with a
// stage program that fits the prepared stage and every dummy with the
// canonical dummy authorization, and report the spend's own transaction and
// group IDs.
func validateSignedRotatingGroup(prep *signerapi.RotatingPrepareResponse, prepared []types.Transaction, resp *signerapi.RotatingSignResponse) ([][]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("empty sign response")
	}
	if len(resp.Signed) != len(prepared) {
		return nil, fmt.Errorf("signed group has %d transactions, prepared %d", len(resp.Signed), len(prepared))
	}
	if resp.Stage != prep.Stage || resp.Target != prep.Target {
		return nil, fmt.Errorf("signer reports stage %d to %d, prepared %d to %d", resp.Stage, resp.Target, prep.Stage, prep.Target)
	}
	out := make([][]byte, len(resp.Signed))
	stxns := make([]types.SignedTxn, len(resp.Signed))
	for i, h := range resp.Signed {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("transaction at index %d: invalid hex: %w", i, err)
		}
		stxn, err := DecodeSignedTxnToSubmit(raw)
		if err != nil {
			return nil, fmt.Errorf("transaction at index %d: %w", i, err)
		}
		if !bytes.Equal(txnutil.EncodeWithPrefix(stxn.Txn), txnutil.EncodeWithPrefix(prepared[i])) {
			return nil, fmt.Errorf("transaction at index %d differs from the prepared transaction", i)
		}
		out[i], stxns[i] = raw, stxn
	}
	if err := validateRotatingSpendAuthorization(stxns[0], prep.Stage); err != nil {
		return nil, fmt.Errorf("transaction at index 0: %w", err)
	}
	spend := prepared[0]
	if err := validateCanonicalReturnedDummies(spend, spend.Group, stxns, out, 1); err != nil {
		return nil, err
	}
	if txID := sdkcrypto.GetTxID(spend); resp.TxID != txID {
		return nil, fmt.Errorf("signer reports transaction ID %s, the spend's is %s", resp.TxID, txID)
	}
	// The signer encodes the group ID even when it is zero, for a spend
	// that needed no dummies; an empty one is accepted for that case too.
	groupID := base64.StdEncoding.EncodeToString(spend.Group[:])
	if resp.GroupID != groupID && (spend.Group != (types.Digest{}) || resp.GroupID != "") {
		return nil, fmt.Errorf("signer reports group ID %q, the spend's is %q", resp.GroupID, groupID)
	}
	return out, nil
}

// validateRotatingSpendAuthorization checks that a signed rotating spend is
// authorized by a stage program and nothing else, and that the program fits
// the prepared stage: at stage 0 its address is the account itself, after it
// is another address the signed transaction names as its signer, and it is
// never the address the spend hands the account to. Which stage's program it
// is the ledger checks: the client cannot derive stage addresses.
func validateRotatingSpendAuthorization(stxn types.SignedTxn, stage uint64) error {
	lsig := stxn.Lsig
	if len(lsig.Logic) == 0 {
		return fmt.Errorf("spend is not authorized by a stage program")
	}
	if stxn.Sig != (types.Signature{}) || !stxn.Msig.Blank() || !stxn.PQsig.Blank() {
		return fmt.Errorf("spend carries more than one authorization")
	}
	if lsig.Sig != (types.Signature{}) || !lsig.Msig.Blank() || !lsig.LMsig.Blank() || !lsig.PQsig.Blank() {
		return fmt.Errorf("spend's stage program is delegated by a signature, which the signer never returns")
	}
	program := sdkcrypto.LogicSigAddress(types.LogicSig{Logic: lsig.Logic})
	spend := stxn.Txn
	if program == spend.RekeyTo {
		return fmt.Errorf("spend is authorized by the next stage's program")
	}
	if (program == spend.Sender) != (stage == 0) {
		return fmt.Errorf("spend's stage program does not fit stage %d of the account", stage)
	}
	var wantSigner types.Address
	if program != spend.Sender {
		wantSigner = program
	}
	switch {
	case stxn.AuthAddr == wantSigner:
	case wantSigner.IsZero():
		return fmt.Errorf("spend names signer %s, but at stage 0 the account signs for itself", stxn.AuthAddr)
	case stxn.AuthAddr.IsZero():
		return fmt.Errorf("spend does not name its signer %s, the stage program's address", program)
	default:
		return fmt.Errorf("spend names signer %s, not its stage program's address %s", stxn.AuthAddr, program)
	}
	return nil
}
