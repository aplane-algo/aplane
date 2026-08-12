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
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// TransactionPrepResult contains the prepared transaction and context
type TransactionPrepResult struct {
	Transaction    types.Transaction
	SigningContext *SigningContext
	AssetInfo      *ASAInfo               // For ASA transactions
	AmountInUnits  uint64                 // Amount in base units
	LsigArgs       map[string][]byte      // Optional LogicSig arguments (for generic LogicSigs like HTLC)
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

// BalanceCheckResult contains balance validation results
type BalanceCheckResult struct {
	SenderBalance    float64
	RequiredAmount   float64
	SufficientFunds  bool
	ReceiverOptedIn  bool // For ASA transfers
	NewAccount       bool // Receiver is a new account
	BelowMinBalance  bool // Sender will be below min balance after tx
	MinBalance       uint64
	RemainingBalance uint64
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

func (e *Engine) validateSubmitLsigArgs(txns []types.Transaction, lsigArgsMap []map[string][]byte) error {
	for i, txn := range txns {
		var lsigArgs map[string][]byte
		if i < len(lsigArgsMap) {
			lsigArgs = lsigArgsMap[i]
		}

		sender := txn.Sender.String()
		if e.signerCacheIsGenericLsig(sender) || len(lsigArgs) > 0 {
			if err := e.validateSignerLsigArgs(sender, lsigArgs); err != nil {
				return fmt.Errorf("transaction %d: invalid LogicSig arguments: %w", i+1, err)
			}
		}
	}
	return nil
}

// signAndSubmitGroup validates preconditions and signs+submits a transaction group.
func (e *Engine) signAndSubmitGroup(txns []types.Transaction, opts clientsign.SubmitOptions) ([]string, []types.Transaction, error) {
	if err := e.validateSubmitLsigArgs(txns, opts.LsigArgsMap); err != nil {
		return nil, nil, err
	}
	if !e.IsConnected() {
		return nil, nil, ErrNotConnected
	}
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}
	if err := e.refreshSubmitSigningState(opts.Ctx, txns); err != nil {
		return nil, nil, err
	}
	if gs := e.guardedSigner(); gs.HasGuardedEffectiveSigner(txns) {
		return gs.SignAndSubmitGroup(txns, opts)
	}
	return e.Connection.SignAndSubmitGroup(txns, &e.AuthCache, e.AlgodClient, opts)
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
		if e.signerCacheGuardedSigningMetadataNeedsRefresh(effectiveSigner) {
			return true
		}
	}
	return false
}

// SignAndSubmit signs and submits a prepared transaction using the
// caller's context for signer and algod operations.
func (e *Engine) SignAndSubmit(ctx context.Context, prep *TransactionPrepResult, wait bool) (*SubmitResult, error) {
	// Build lsigArgsMap if LsigArgs are provided
	var lsigArgsMap []map[string][]byte
	if len(prep.LsigArgs) > 0 {
		lsigArgsMap = []map[string][]byte{prep.LsigArgs}
	}

	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	opts := e.defaultSubmitOptions(ctx, wait, &writeNotices, &output)
	opts.LsigArgsMap = lsigArgsMap
	if prep.AppCallInfo != nil {
		opts.AppCallInfo = []*signerapi.AppCallInfo{prep.AppCallInfo}
	}

	txids, submittedTxns, err := e.signAndSubmitGroup([]types.Transaction{prep.Transaction}, opts)
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

func (e *Engine) SignAndSubmitGroup(ctx context.Context, txns []types.Transaction, lsigArgs []map[string][]byte) (*SignTransactionsResult, error) {
	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	opts := e.defaultSubmitOptions(ctx, true, &writeNotices, &output)
	opts.LsigArgsMap = lsigArgs
	txIDs, submittedTxns, err := e.signAndSubmitGroup(txns, opts)
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

// SignAndSubmitTransactions signs and submits pre-built transactions.
// The transactions are already constructed; this only handles signing/submission.
func (e *Engine) SignAndSubmitTransactions(ctx context.Context, txns []types.Transaction, wait bool) (*SignTransactionsResult, error) {
	if len(txns) == 0 {
		return nil, fmt.Errorf("no transactions provided")
	}

	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	txIDs, submittedTxns, err := e.signAndSubmitGroup(txns, e.defaultSubmitOptions(ctx, wait, &writeNotices, &output))
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
