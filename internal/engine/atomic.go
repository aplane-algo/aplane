// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Atomic transaction group operations

import (
	"bytes"
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// AtomicPaymentParams for a single ALGO payment in an atomic group.
// All addresses must be pre-resolved 58-character Algorand addresses.
type AtomicPaymentParams struct {
	From   string // Pre-resolved sender address (58-char)
	To     string // Pre-resolved receiver address (58-char)
	Amount uint64 // Amount in microAlgos
	Note   string // Optional note
}

// AtomicASAParams for a single ASA transfer in an atomic group.
// All addresses must be pre-resolved 58-character Algorand addresses.
type AtomicASAParams struct {
	From    string // Pre-resolved sender address (58-char)
	To      string // Pre-resolved receiver address (58-char)
	AssetID uint64 // Pre-resolved asset ID
	Amount  uint64 // Amount in base units
	Note    string // Optional note
}

// AtomicGroupParams contains common parameters for atomic groups.
type AtomicGroupParams struct {
	Fee        uint64 // Optional custom fee in microAlgos (per transaction)
	UseFlatFee bool   // If true, use Fee as flat fee
}

// AtomicPrepResult contains prepared atomic transaction group.
type AtomicPrepResult struct {
	Transactions    []types.Transaction
	SigningContexts []*SigningContext
	AssetInfo       *ASAInfo // For ASA transfers (nil for ALGO)
}

// AtomicSubmitResult contains result of atomic group submission.
type AtomicSubmitResult struct {
	TxIDs        []string
	Transactions []types.Transaction
	Confirmed    bool
	Output       string
	WriteNotices []TransactionWriteNotice
}

func (e *Engine) PrepareAtomicPaymentsWithContext(ctx context.Context, payments []AtomicPaymentParams, groupParams AtomicGroupParams) (*AtomicPrepResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if len(payments) == 0 {
		return nil, fmt.Errorf("no payments provided")
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFeeWithContext(ctx, groupParams.Fee, groupParams.UseFlatFee)
	if err != nil {
		return nil, err
	}

	// Build signing contexts and transactions
	txns := make([]types.Transaction, len(payments))
	contexts := make([]*SigningContext, len(payments))

	for i, p := range payments {
		// Build signing context for sender
		signingCtx, err := e.BuildSigningContextWithContext(ctx, p.From)
		if err != nil {
			return nil, fmt.Errorf("payment %d: failed to build signing context: %w", i+1, err)
		}
		contexts[i] = signingCtx

		// Create transaction
		txnObj, err := transaction.MakePaymentTxn(
			p.From,
			p.To,
			p.Amount,
			[]byte(p.Note),
			"",
			sp,
		)
		if err != nil {
			return nil, fmt.Errorf("payment %d: failed to create transaction: %w", i+1, err)
		}
		txns[i] = txnObj
	}

	return &AtomicPrepResult{
		Transactions:    txns,
		SigningContexts: contexts,
	}, nil
}

func (e *Engine) PrepareAtomicASATransfersWithContext(ctx context.Context, transfers []AtomicASAParams, groupParams AtomicGroupParams) (*AtomicPrepResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if len(transfers) == 0 {
		return nil, fmt.Errorf("no transfers provided")
	}

	// Verify all transfers use the same asset ID
	assetID := transfers[0].AssetID
	for i, t := range transfers {
		if t.AssetID != assetID {
			return nil, fmt.Errorf("transfer %d: all transfers in atomic group must use same asset ID", i+1)
		}
	}

	// Get ASA info
	asaInfo, err := e.GetASAInfoWithContext(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ASA info: %w", err)
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFeeWithContext(ctx, groupParams.Fee, groupParams.UseFlatFee)
	if err != nil {
		return nil, err
	}

	// Build signing contexts and transactions
	txns := make([]types.Transaction, len(transfers))
	contexts := make([]*SigningContext, len(transfers))

	for i, t := range transfers {
		// Build signing context for sender
		signingCtx, err := e.BuildSigningContextWithContext(ctx, t.From)
		if err != nil {
			return nil, fmt.Errorf("transfer %d: failed to build signing context: %w", i+1, err)
		}
		contexts[i] = signingCtx

		// Create transaction
		txnObj, err := transaction.MakeAssetTransferTxn(
			t.From,
			t.To,
			t.Amount,
			[]byte(t.Note),
			sp,
			"",
			t.AssetID,
		)
		if err != nil {
			return nil, fmt.Errorf("transfer %d: failed to create transaction: %w", i+1, err)
		}
		txns[i] = txnObj
	}

	return &AtomicPrepResult{
		Transactions:    txns,
		SigningContexts: contexts,
		AssetInfo:       asaInfo,
	}, nil
}

func (e *Engine) SignAndSubmitAtomicWithContext(ctx context.Context, prep *AtomicPrepResult, wait bool) (*AtomicSubmitResult, error) {
	if len(prep.Transactions) == 0 {
		return nil, fmt.Errorf("no transactions to submit")
	}

	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	txids, submittedTxns, err := e.signAndSubmitGroup(prep.Transactions, e.defaultSubmitOptionsWithContext(ctx, wait, &writeNotices, &output))
	result := &AtomicSubmitResult{
		TxIDs:        txids,
		Transactions: originalSubmittedTransactions(prep.Transactions, submittedTxns),
		Confirmed:    wait && !e.Simulate && err == nil,
		Output:       output.String(),
		WriteNotices: writeNotices,
	}
	if err != nil {
		return result, fmt.Errorf("failed to sign and submit atomic group: %w", errorWithSubmissionOutput(err, output.String()))
	}

	return result, nil
}

func (e *Engine) ValidateAtomicPaymentsWithContext(ctx context.Context, payments []AtomicPaymentParams, fee uint64) ([]BalanceCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	results := make([]BalanceCheckResult, len(payments))
	txnFee := fee
	if txnFee == 0 {
		txnFee = 1000 // Default fee
	}

	for i, p := range payments {
		check, err := e.checkPaymentBalancesWithContext(ctx, p.From, p.To, p.Amount, txnFee, true)
		if err != nil {
			return nil, fmt.Errorf("payment %d: %w", i+1, err)
		}
		results[i] = *check
	}

	return results, nil
}

func (e *Engine) ValidateAtomicASATransfersWithContext(ctx context.Context, transfers []AtomicASAParams) ([]BalanceCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if len(transfers) == 0 {
		return nil, nil
	}

	results := make([]BalanceCheckResult, len(transfers))

	for i, t := range transfers {
		check, err := e.checkASABalancesWithContext(ctx, t.From, t.To, t.AssetID, t.Amount)
		if err != nil {
			return nil, fmt.Errorf("transfer %d: %w", i+1, err)
		}
		results[i] = *check
	}

	return results, nil
}
