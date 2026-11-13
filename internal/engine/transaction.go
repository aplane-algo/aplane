// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Transaction signing and submission methods.
// All methods operate on raw Algorand addresses — alias resolution and
// set expansion must be done by the caller (typically the REPL/UI layer).
package engine

import (
	"bytes"
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// TransactionPrepResult contains the prepared transaction and context
type TransactionPrepResult struct {
	Transaction    types.Transaction
	SigningContext *SigningContext
	AssetInfo      *ASAInfo               // For ASA transactions
	AmountInUnits  uint64                 // Amount in base units
	AppCallInfo    *signerapi.AppCallInfo // Optional app-call metadata for signer approval rendering
}

// SubmitResult contains the result of submitting a transaction
type SubmitResult struct {
	TxID         string
	Transaction  types.Transaction
	Confirmed    bool
	Output       string
	WriteNotices []TransactionWriteNotice
	// AuthRefreshWarning is set (non-fatal) when a confirmed rekey committed but
	// the follow-up auth-cache refresh failed, leaving the local cache stale.
	AuthRefreshWarning string
}

// ConfirmationResult contains confirmation-wait presentation output.
type ConfirmationResult struct {
	Output string
}

// BalanceCheckResult contains balance validation results. SenderBalance and
// RequiredAmount are in base units: microAlgos for a payment, the asset's base
// units for an ASA transfer.
type BalanceCheckResult struct {
	SenderBalance  uint64
	RequiredAmount uint64
	// RequiredOverflows is set when a payment's amount plus fee exceeds the
	// largest uint64. RequiredAmount is then clamped to that largest value
	// and is not the requirement, so a message says this instead of it.
	RequiredOverflows bool
	SufficientFunds   bool
	ReceiverOptedIn   bool // For ASA transfers
	NewAccount        bool // Receiver is a new account
	BelowMinBalance   bool // Sender will be below min balance after tx
	MinBalance        uint64
	RemainingBalance  uint64
}

func (e *Engine) defaultSubmitOptions(ctx context.Context, wait bool, writeNotices *[]TransactionWriteNotice, out *bytes.Buffer) clientsign.SubmitOptions {
	if out == nil {
		out = &bytes.Buffer{}
	}
	return clientsign.SubmitOptions{
		Ctx:                 ctx,
		WaitForConfirmation: wait,
		Verbose:             e.Verbose,
		Simulate:            e.Simulate,
		Out:                 out,
		TxnWriter:           e.WriteTxnCallback(writeNotices),
	}
}

// validateSubmitLsigArgs checks each transaction's placed arguments against
// the declared arguments of the key that signs for its sender, from the
// signer cache: the sender's own key, or the key it is rekeyed to. It runs
// after refreshSubmitSigningState, so the auth address and the key list it
// reads are the ones the submission signs with. A key whose arguments the
// cache does not describe passes, and the signer judges.
func (e *Engine) validateSubmitLsigArgs(txns []types.Transaction, lsigArgsMap []map[string][]byte) error {
	for i, txn := range txns {
		var lsigArgs map[string][]byte
		if i < len(lsigArgsMap) {
			lsigArgs = lsigArgsMap[i]
		}

		signer := e.AuthCache.ResolveEffectiveSigner(txn.Sender.String())
		if e.signerCacheIsGenericLsig(signer) || len(lsigArgs) > 0 {
			if err := e.validateSignerLsigArgs(signer, lsigArgs); err != nil {
				return fmt.Errorf("transaction %d: invalid LogicSig arguments: %w", i+1, err)
			}
		}
	}
	return nil
}

// signAndSubmitGroup places the submission's LogicSig arguments on its
// transactions, validates preconditions and signs+submits the group through
// the route its senders take. Every route gets the placed arguments, one map
// per position.
func (e *Engine) signAndSubmitGroup(txns []types.Transaction, args LsigArgs, opts clientsign.SubmitOptions) ([]string, []types.Transaction, error) {
	opts.LsigArgsMap = args.place(txns)
	if err := e.checkReadyToSign(txns, opts); err != nil {
		return nil, nil, err
	}
	// Rotating accounts route on the sender's own signing flow: their
	// effective signer is a stage address the signer never lists.
	if rotating, err := e.rotatingSender(txns, opts); err != nil {
		return nil, nil, err
	} else if rotating {
		return e.Connection.SignAndSubmitRotating(txns[0], e.AlgodClient, clientsign.RotatingOptions{SubmitOptions: opts})
	}
	if gs := e.cosignedSigner(); gs.HasCosignedEffectiveSigner(txns) {
		return gs.SignAndSubmitGroup(txns, opts)
	}
	return e.Connection.SignAndSubmitGroup(txns, &e.AuthCache, e.AlgodClient, opts)
}

// checkReadyToSign runs the preconditions every signing path shares: a
// connected signer and algod, a supported consensus version, transactions for
// the active algod's network, fresh signer metadata for the senders, and then,
// against that metadata, the placed LogicSig arguments. Plugin drafts in the
// default group mode and transaction files reach the signer through here.
func (e *Engine) checkReadyToSign(txns []types.Transaction, opts clientsign.SubmitOptions) error {
	if !e.IsConnected() {
		return ErrNotConnected
	}
	if e.AlgodClient == nil {
		return ErrNoAlgodClient
	}
	if err := e.checkActiveNetwork(opts.Ctx, txns); err != nil {
		return err
	}
	if err := e.refreshSubmitSigningState(opts.Ctx, txns); err != nil {
		return err
	}
	return e.validateSubmitLsigArgs(txns, opts.LsigArgsMap)
}

func (e *Engine) refreshSubmitSigningState(ctx context.Context, txns []types.Transaction) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := e.refreshMissingSubmitAuthAddresses(ctx, txns); err != nil {
		return err
	}

	if !e.submitEffectiveSignersNeedKeyRefresh(txns) {
		return nil
	}
	if _, err := e.RefreshKeys(ctx); err != nil {
		return fmt.Errorf("failed to refresh signer keys: %w", err)
	}
	return nil
}

func (e *Engine) refreshMissingSubmitAuthAddresses(ctx context.Context, txns []types.Transaction) error {
	seenSenders := make(map[string]struct{}, len(txns))
	for _, txn := range txns {
		sender := txn.Sender.String()
		if _, ok := seenSenders[sender]; ok {
			continue
		}
		seenSenders[sender] = struct{}{}
		if _, cached := e.AuthCache.GetAuthAddress(sender); cached {
			continue
		}
		if _, err := e.RefreshAuthAddressWithContext(ctx, sender); err != nil {
			return fmt.Errorf("failed to refresh auth address for %s: %w", sender, err)
		}
	}
	return nil
}

// refreshRekeyedSenders re-queries and overwrites the auth-address cache for the
// senders of confirmed rekey transactions. It is the post-submit counterpart to
// refreshMissingSubmitAuthAddresses: that hook is fill-on-miss, so after a rekey
// it cannot correct the entry it just cached as the pre-rekey authorizer. This
// hook overwrites that stale entry with the new on-chain authorizer.
//
// It returns the first refresh error encountered. Such a failure is non-fatal —
// the rekey already committed — but the local cache is left stale, so the caller
// should surface it as a warning (and the user can run `rekey refresh`).
func (e *Engine) refreshRekeyedSenders(ctx context.Context, txns []types.Transaction) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var zero types.Address
	var firstErr error
	seen := make(map[string]struct{}, len(txns))
	for _, txn := range txns {
		if txn.RekeyTo == zero {
			continue
		}
		sender := txn.Sender.String()
		if _, ok := seen[sender]; ok {
			continue
		}
		seen[sender] = struct{}{}
		if _, err := e.RefreshAuthAddressWithContext(ctx, sender); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to refresh auth address for %s: %w", sender, err)
		}
	}
	return firstErr
}

func (e *Engine) submitEffectiveSignersNeedKeyRefresh(txns []types.Transaction) bool {
	seenSigners := make(map[string]struct{}, len(txns))
	for _, txn := range txns {
		sender := txn.Sender.String()
		effectiveSigner := e.AuthCache.ResolveEffectiveSigner(sender)
		if _, ok := seenSigners[effectiveSigner]; ok {
			continue
		}
		seenSigners[effectiveSigner] = struct{}{}
		if effectiveSigner != sender {
			return true
		}
		if e.signerCacheKeyType(effectiveSigner) == "" {
			return true
		}
	}
	return false
}

// SignAndSubmit signs and submits a prepared transaction, with the
// arguments args gives its sender, using the caller's context for signer and
// algod operations.
func (e *Engine) SignAndSubmit(ctx context.Context, prep *TransactionPrepResult, args LsigArgs, wait bool) (*SubmitResult, error) {
	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	opts := e.defaultSubmitOptions(ctx, wait, &writeNotices, &output)
	if prep.AppCallInfo != nil {
		opts.AppCallInfo = []*signerapi.AppCallInfo{prep.AppCallInfo}
	}

	txids, submittedTxns, err := e.signAndSubmitGroup([]types.Transaction{prep.Transaction}, args, opts)
	submittedTxn := prep.Transaction
	if len(submittedTxns) > 0 {
		submittedTxn = submittedTxns[0]
	}
	result := &SubmitResult{
		Transaction:  submittedTxn,
		Confirmed:    wait && !e.Simulate && err == nil,
		Output:       output.String(),
		WriteNotices: writeNotices,
	}
	if len(txids) > 0 {
		result.TxID = txids[0]
	}
	if err != nil {
		return result, fmt.Errorf("failed to sign and submit: %w", errorWithSubmissionOutput(err, output.String()))
	}

	// A confirmed rekey changes the sender's on-chain authorizer; refresh the
	// stale auth-cache entry captured before signing. All rekeys flow through this
	// path (only PrepareRekey sets RekeyTo). Best-effort: a failure is reported as
	// a warning on the result, not an error, since the rekey already committed.
	if result.Confirmed {
		if refreshErr := e.refreshRekeyedSenders(ctx, []types.Transaction{submittedTxn}); refreshErr != nil {
			result.AuthRefreshWarning = refreshErr.Error()
		}
	}

	return result, nil
}

// WaitForConfirmation waits for a transaction to be confirmed
func (e *Engine) WaitForConfirmation(ctx context.Context, txid string, rounds uint64) error {
	_, err := e.WaitForConfirmationResult(ctx, txid, rounds)
	return err
}

// WaitForConfirmationResult waits for a transaction to be confirmed
// and returns progress output for callers to render.
func (e *Engine) WaitForConfirmationResult(ctx context.Context, txid string, rounds uint64) (*ConfirmationResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	var output bytes.Buffer
	if err := algo.WaitForConfirmation(ctx, e.AlgodClient, txid, rounds, &output); err != nil {
		return &ConfirmationResult{Output: output.String()}, err
	}
	return &ConfirmationResult{Output: output.String()}, nil
}

// CanSignForAddress checks if we can sign for the given address.
// Returns (canSign, isLsig). New callers that need to distinguish native
// authorization kinds should use CanSignForAddressWithKind.
func (e *Engine) CanSignForAddress(address string) (bool, bool) {
	canSign, kind := e.CanSignForAddressWithKind(address)
	return canSign, kind == algorithm.AuthorizationLogicSig
}

// CanSignForAddressWithKind checks whether the signer owns an address and
// returns the authorization envelope its key type produces.
func (e *Engine) CanSignForAddressWithKind(address string) (bool, algorithm.AuthorizationKind) {
	kind, present := e.signerCacheAuthorizationKind(address)
	return present && kind != "", kind
}

// SignAndSubmitGroup signs and submits txns as one group, each transaction
// with the arguments args gives its sender, and waits for confirmation.
func (e *Engine) SignAndSubmitGroup(ctx context.Context, txns []types.Transaction, args LsigArgs) (*SignTransactionsResult, error) {
	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	opts := e.defaultSubmitOptions(ctx, true, &writeNotices, &output)
	txIDs, submittedTxns, err := e.signAndSubmitGroup(txns, args, opts)
	result := &SignTransactionsResult{
		TxIDs:        txIDs,
		Transactions: originalSubmittedTransactions(txns, submittedTxns),
		Confirmed:    !e.Simulate && len(txIDs) > 0 && err == nil,
		Output:       output.String(),
		WriteNotices: writeNotices,
	}
	if err != nil {
		return result, errorWithSubmissionOutput(err, output.String())
	}
	return result, nil
}

// SignTransactionsResult contains the result of signing pre-built transactions.
type SignTransactionsResult struct {
	TxIDs        []string                 // Transaction IDs
	Transactions []types.Transaction      // The transactions that were signed
	Confirmed    bool                     // True if all were confirmed (when wait=true)
	Output       string                   // Signer/submission output
	WriteNotices []TransactionWriteNotice // Transaction JSON write outcomes
}

// SignAndSubmitTransactions signs and submits pre-built transactions, such
// as a transaction file's, with no LogicSig arguments.
// The transactions are already constructed; this only handles signing/submission.
func (e *Engine) SignAndSubmitTransactions(ctx context.Context, txns []types.Transaction, wait bool) (*SignTransactionsResult, error) {
	if len(txns) == 0 {
		return nil, fmt.Errorf("no transactions provided")
	}

	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	txIDs, submittedTxns, err := e.signAndSubmitGroup(txns, LsigArgs{}, e.defaultSubmitOptions(ctx, wait, &writeNotices, &output))
	result := &SignTransactionsResult{
		TxIDs:        txIDs,
		Transactions: originalSubmittedTransactions(txns, submittedTxns),
		Confirmed:    wait && !e.Simulate && len(txIDs) > 0 && err == nil,
		Output:       output.String(),
		WriteNotices: writeNotices,
	}
	if err != nil {
		return result, errorWithSubmissionOutput(err, output.String())
	}

	return result, nil
}

func originalSubmittedTransactions(original, submitted []types.Transaction) []types.Transaction {
	if len(original) == 0 {
		return nil
	}
	if len(submitted) == 0 {
		return append([]types.Transaction(nil), original...)
	}
	count := len(original)
	if len(submitted) < count {
		count = len(submitted)
	}
	out := make([]types.Transaction, count)
	copy(out, submitted[:count])
	return out
}
