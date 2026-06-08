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
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
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

func (e *Engine) defaultSubmitOptionsWithContext(ctx context.Context, wait bool, writeNotices *[]TransactionWriteNotice, out *bytes.Buffer) signing.SubmitOptions {
	if out == nil {
		out = &bytes.Buffer{}
	}
	return signing.SubmitOptions{
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
func (e *Engine) signAndSubmitGroup(txns []types.Transaction, opts signing.SubmitOptions) ([]string, []types.Transaction, error) {
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
	if e.hasGuardedEffectiveSigner(txns) {
		return e.signAndSubmitGuardedGroup(txns, opts)
	}
	return e.Connection.SignAndSubmitGroup(txns, &e.AuthCache, e.AlgodClient, opts)
}

func (e *Engine) refreshSubmitSigningState(ctx context.Context, txns []types.Transaction) error {
	if ctx == nil {
		ctx = context.Background()
	}
	seenSenders := make(map[string]struct{}, len(txns))
	for _, txn := range txns {
		sender := txn.Sender.String()
		if _, ok := seenSenders[sender]; ok {
			continue
		}
		seenSenders[sender] = struct{}{}
		if _, err := e.RefreshAuthAddressWithContext(ctx, sender); err != nil {
			return fmt.Errorf("failed to refresh auth address for %s: %w", sender, err)
		}
	}

	if !e.submitEffectiveSignersNeedKeyRefresh(txns) {
		return nil
	}
	if _, err := e.RefreshKeysWithContext(ctx); err != nil {
		return fmt.Errorf("failed to refresh signer keys: %w", err)
	}
	return nil
}

func (e *Engine) submitEffectiveSignersNeedKeyRefresh(txns []types.Transaction) bool {
	seenSigners := make(map[string]struct{}, len(txns))
	for _, txn := range txns {
		effectiveSigner := e.AuthCache.ResolveEffectiveSigner(txn.Sender.String())
		if _, ok := seenSigners[effectiveSigner]; ok {
			continue
		}
		seenSigners[effectiveSigner] = struct{}{}
		if e.signerCacheKeyType(effectiveSigner) == "" {
			return true
		}
	}
	return false
}

// SignAndSubmitWithContext signs and submits a prepared transaction using the
// caller's context for signer and algod operations.
func (e *Engine) SignAndSubmitWithContext(ctx context.Context, prep *TransactionPrepResult, wait bool) (*SubmitResult, error) {
	// Build lsigArgsMap if LsigArgs are provided
	var lsigArgsMap []map[string][]byte
	if len(prep.LsigArgs) > 0 {
		lsigArgsMap = []map[string][]byte{prep.LsigArgs}
	}

	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	opts := e.defaultSubmitOptionsWithContext(ctx, wait, &writeNotices, &output)
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

	return result, nil
}

// WaitForConfirmation waits for a transaction to be confirmed
func (e *Engine) WaitForConfirmationWithContext(ctx context.Context, txid string, rounds uint64) error {
	_, err := e.WaitForConfirmationResultWithContext(ctx, txid, rounds)
	return err
}

// WaitForConfirmationResultWithContext waits for a transaction to be confirmed
// and returns progress output for callers to render.
func (e *Engine) WaitForConfirmationResultWithContext(ctx context.Context, txid string, rounds uint64) (*ConfirmationResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	var output bytes.Buffer
	if err := algo.WaitForConfirmationWithContext(ctx, e.AlgodClient, txid, rounds, &output); err != nil {
		return &ConfirmationResult{Output: output.String()}, err
	}
	return &ConfirmationResult{Output: output.String()}, nil
}

// CanSignForAddress checks if we can sign for the given address.
// Returns (canSign, isLsig).
func (e *Engine) CanSignForAddress(address string) (bool, bool) {
	// Check if we have this address in the signer cache
	hasRemoteSigner := e.signerCacheHasAddress(address)
	if !hasRemoteSigner {
		return false, false
	}

	// Check if it's an LSig type by key type
	keyType := e.signerCacheKeyType(address)
	isLsig := e.signerCacheIsGenericLsig(address) || (keyType != "" && keyType != "ed25519")

	return true, isLsig
}

// SignAndSubmitGroup signs and submits a group of transactions with optional per-transaction
// LogicSig arguments. This wraps signing.SignAndSubmitViaGroup with the engine's internal state.
func (e *Engine) SignAndSubmitGroup(txns []types.Transaction, lsigArgs []map[string][]byte) ([]string, error) {
	result, err := e.SignAndSubmitGroupWithContext(context.Background(), txns, lsigArgs)
	if result == nil {
		return nil, err
	}
	return result.TxIDs, err
}

func (e *Engine) SignAndSubmitGroupWithContext(ctx context.Context, txns []types.Transaction, lsigArgs []map[string][]byte) (*SignTransactionsResult, error) {
	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	opts := e.defaultSubmitOptionsWithContext(ctx, true, &writeNotices, &output)
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

// SignAndSubmitTransactionsWithContext signs and submits pre-built transactions.
// The transactions are already constructed; this only handles signing/submission.
func (e *Engine) SignAndSubmitTransactionsWithContext(ctx context.Context, txns []types.Transaction, wait bool) (*SignTransactionsResult, error) {
	if len(txns) == 0 {
		return nil, fmt.Errorf("no transactions provided")
	}

	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	txIDs, submittedTxns, err := e.signAndSubmitGroup(txns, e.defaultSubmitOptionsWithContext(ctx, wait, &writeNotices, &output))
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
