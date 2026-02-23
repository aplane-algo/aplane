// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

// Account rekey operations

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// RekeyParams contains parameters for rekeying an account.
// All addresses must be resolved 58-character Algorand addresses.
type RekeyParams struct {
	From       string // Account to rekey (58-char)
	To         string // New auth address (58-char)
	Fee        uint64 // Optional custom fee in microAlgos
	UseFlatFee bool   // If true, use Fee as flat fee
}

// RekeyCheckResult contains validation results for a rekey operation.
type RekeyCheckResult struct {
	TargetIsRekeyed bool   // True if target is itself rekeyed (error condition)
	TargetAuthAddr  string // Target's current auth address (if rekeyed)
	IsUnrekey       bool   // True if rekeying back to self
}

// PrepareRekey validates and prepares a rekey transaction.
// Addresses must be pre-resolved (no aliases).
func (e *Engine) PrepareRekey(params RekeyParams) (*TransactionPrepResult, *RekeyCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}

	checkResult := &RekeyCheckResult{
		IsUnrekey: params.From == params.To,
	}

	// Check if target address is itself rekeyed (unless unrekeying)
	if !checkResult.IsUnrekey {
		toAcctInfo, err := e.AlgodClient.AccountInformation(params.To).Do(context.Background())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query target account info: %w", err)
		}

		if toAcctInfo.AuthAddr != "" && toAcctInfo.AuthAddr != params.To {
			checkResult.TargetIsRekeyed = true
			checkResult.TargetAuthAddr = toAcctInfo.AuthAddr
			return nil, checkResult, fmt.Errorf("cannot rekey to %s because it is itself rekeyed to %s",
				params.To, toAcctInfo.AuthAddr)
		}
	}

	// Build signing context for sender
	ctx, err := e.BuildSigningContext(params.From)
	if err != nil {
		return nil, checkResult, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFee(params.Fee, params.UseFlatFee)
	if err != nil {
		return nil, checkResult, err
	}

	// Create rekey transaction (payment to self with rekey field)
	txnObj, err := transaction.MakePaymentTxn(
		params.From,
		params.From, // Send to self
		0,           // 0 amount
		nil,         // No note
		"",          // No close remainder to
		sp,
	)
	if err != nil {
		return nil, checkResult, fmt.Errorf("failed to create rekey transaction: %w", err)
	}

	// Set rekey address
	rekeyAddr, err := types.DecodeAddress(params.To)
	if err != nil {
		return nil, checkResult, fmt.Errorf("invalid rekey address: %w", err)
	}
	txnObj.RekeyTo = rekeyAddr

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: ctx,
	}, checkResult, nil
}
