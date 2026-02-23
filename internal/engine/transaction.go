// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package engine transaction methods operate on raw Algorand addresses only.
// Alias resolution (e.g., "alice" → "ABC123...") and set expansion
// (e.g., "@validators" → ["ABC...", "DEF..."]) must be done by the caller
// (typically the REPL/UI layer) before invoking these methods.
package engine

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/signing"
)

// TransactionPrepResult contains the prepared transaction and context
type TransactionPrepResult struct {
	Transaction    types.Transaction
	SigningContext *SigningContext
	AssetInfo      *ASAInfo          // For ASA transactions
	AmountInUnits  uint64            // Amount in base units
	LsigArgs       map[string][]byte // Optional LogicSig arguments (for generic LogicSigs like hashlock)
}

// SubmitResult contains the result of submitting a transaction
type SubmitResult struct {
	TxID        string
	Transaction types.Transaction
	Confirmed   bool
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

// SignAndSubmit signs and submits a prepared transaction
func (e *Engine) SignAndSubmit(prep *TransactionPrepResult, wait bool) (*SubmitResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if e.SignerClient == nil {
		return nil, ErrNotConnected
	}

	// Build lsigArgsMap if LsigArgs are provided
	var lsigArgsMap []map[string][]byte
	if len(prep.LsigArgs) > 0 {
		lsigArgsMap = []map[string][]byte{prep.LsigArgs}
	}

	// Validate lsig args against schema (checks required args, validates names)
	// This runs even if no args provided, to catch missing required args
	sender := prep.Transaction.Sender.String()
	if e.SignerCache.IsGenericLsig(sender) || len(prep.LsigArgs) > 0 {
		if err := e.SignerCache.ValidateLsigArgs(sender, prep.LsigArgs); err != nil {
			return nil, fmt.Errorf("invalid LogicSig arguments: %w", err)
		}
	}

	// Sign and submit using /sign endpoint (server handles dummies, fees, grouping)
	txns := []types.Transaction{prep.Transaction}
	txids, err := signing.SignAndSubmitViaGroup(
		txns,
		&e.AuthCache,
		e.SignerClient,
		e.AlgodClient,
		signing.SubmitOptions{
			WaitForConfirmation: wait,
			Verbose:             e.Verbose,
			LsigArgsMap:         lsigArgsMap,
			Simulate:            e.Simulate,
			TxnWriter:           e.WriteTxnCallback(),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to sign and submit: %w", err)
	}

	result := &SubmitResult{
		TxID:        txids[0],
		Transaction: prep.Transaction,
		Confirmed:   wait && !e.Simulate,
	}

	return result, nil
}

// WaitForConfirmation waits for a transaction to be confirmed
func (e *Engine) WaitForConfirmation(txid string, rounds uint64) error {
	if e.AlgodClient == nil {
		return ErrNoAlgodClient
	}
	return algo.WaitForConfirmation(e.AlgodClient, txid, rounds)
}

// CanSignForAddress checks if we can sign for the given address.
// Returns (canSign, isLsig).
func (e *Engine) CanSignForAddress(address string) (bool, bool) {
	// Check if we have this address in the signer cache
	hasRemoteSigner := e.SignerCache.HasAddress(address)
	if !hasRemoteSigner {
		return false, false
	}

	// Check if it's an LSig type by key type
	keyType := e.SignerCache.GetKeyType(address)
	isLsig := e.SignerCache.IsGenericLsig(address) || (keyType != "" && keyType != "ed25519")

	return true, isLsig
}

// SignTransactionsResult contains the result of signing pre-built transactions.
type SignTransactionsResult struct {
	TxIDs        []string            // Transaction IDs
	Transactions []types.Transaction // The transactions that were signed
	Confirmed    bool                // True if all were confirmed (when wait=true)
}

// SignAndSubmitTransactionsFromFile signs and submits pre-built transactions.
// This is used by the 'sign' command which loads transactions from files.
// The transactions are already constructed; we just sign and submit them.
func (e *Engine) SignAndSubmitTransactionsFromFile(txns []types.Transaction, wait bool) (*SignTransactionsResult, error) {
	if e.SignerClient == nil {
		return nil, ErrNotConnected
	}
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if len(txns) == 0 {
		return nil, fmt.Errorf("no transactions provided")
	}

	// Use /sign endpoint (server handles dummies, fees, grouping)
	txIDs, err := signing.SignAndSubmitViaGroup(
		txns,
		&e.AuthCache,
		e.SignerClient,
		e.AlgodClient,
		signing.SubmitOptions{
			WaitForConfirmation: wait,
			Verbose:             e.Verbose,
			Simulate:            e.Simulate,
			TxnWriter:           e.WriteTxnCallback(),
		},
	)
	if err != nil {
		return nil, err
	}

	return &SignTransactionsResult{
		TxIDs:        txIDs,
		Transactions: txns,
		Confirmed:    wait && !e.Simulate && len(txIDs) > 0,
	}, nil
}
