// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

// Key registration (online/offline) operations

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// KeyRegParams contains parameters for key registration.
// Address must be resolved 58-character Algorand address.
type KeyRegParams struct {
	Account           string // Resolved address (58-char)
	Mode              string // "online" or "offline"
	VoteKey           string // Base64 encoded vote key
	SelectionKey      string // Base64 encoded selection key
	StateProofKey     string // Base64 encoded state proof key
	VoteFirst         uint64 // First valid round
	VoteLast          uint64 // Last valid round
	KeyDilution       uint64 // Key dilution
	IncentiveEligible bool   // Request incentive eligibility (costs 2 ALGO)
}

// PrepareKeyReg validates and prepares a key registration transaction.
// Address must be pre-resolved (no aliases).
func (e *Engine) PrepareKeyReg(params KeyRegParams) (*TransactionPrepResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Validate online mode parameters
	if params.Mode == "online" {
		if params.VoteKey == "" || params.SelectionKey == "" || params.StateProofKey == "" {
			return nil, fmt.Errorf("online mode requires: votekey, selkey, sproofkey")
		}
		if params.VoteFirst == 0 || params.VoteLast == 0 {
			return nil, fmt.Errorf("online mode requires: votefirst and votelast must be > 0")
		}
		if params.VoteLast <= params.VoteFirst {
			return nil, fmt.Errorf("votelast must be greater than votefirst")
		}
	}

	// Build signing context (handles auth address lookup for rekeyed accounts)
	ctx, err := e.BuildSigningContext(params.Account)
	if err != nil {
		return nil, err
	}

	// Get suggested params
	sp, err := e.AlgodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %w", err)
	}

	// Create key registration transaction using SDK
	txnObj, err := transaction.MakeKeyRegTxnWithStateProofKey(
		params.Account,
		nil, // note
		sp,
		params.VoteKey,
		params.SelectionKey,
		params.StateProofKey,
		params.VoteFirst,
		params.VoteLast,
		params.KeyDilution,
		false, // nonpart - never set to true
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyreg transaction: %w", err)
	}

	// Set incentive fee if eligible (2 ALGO = 2,000,000 microAlgos)
	if params.IncentiveEligible {
		txnObj.Fee = types.MicroAlgos(2000000)
	}

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: ctx,
	}, nil
}

// GetIncentiveEligibility checks if an account is incentive eligible.
// Address must be pre-resolved (no aliases).
func (e *Engine) GetIncentiveEligibility(address string) (bool, error) {
	if e.AlgodClient == nil {
		return false, ErrNoAlgodClient
	}

	acctInfo, err := e.AlgodClient.AccountInformation(address).Do(context.Background())
	if err != nil {
		return false, fmt.Errorf("failed to get account info: %w", err)
	}

	return acctInfo.IncentiveEligible, nil
}
