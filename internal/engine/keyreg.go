// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

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
	Account           string   // Resolved address (58-char)
	Mode              string   // "online" or "offline"
	VoteKey           string   // Base64 encoded vote key
	SelectionKey      string   // Base64 encoded selection key
	StateProofKey     string   // Base64 encoded state proof key
	VoteFirst         uint64   // First valid round
	VoteLast          uint64   // Last valid round
	KeyDilution       uint64   // Key dilution
	IncentiveEligible bool     // Request incentive eligibility (costs 2 ALGO)
	LsigArgs          LsigArgs // LogicSig arguments given for the submission, placed by name when it is signed
}

func (e *Engine) PrepareKeyReg(ctx context.Context, params KeyRegParams) (*TransactionPrepResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Incentive eligibility is asked for when going online and costs a 2 ALGO
	// fee. On any other registration the fee would be paid for nothing.
	if params.Mode != "online" && params.IncentiveEligible {
		return nil, fmt.Errorf("eligible applies only when going online: an %s registration would pay the 2 ALGO incentive fee for nothing", params.Mode)
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
		// The dilution is a property of the participation key. A wrong one
		// registers, but the account can't vote with it, so there is no
		// default to fall back on.
		if params.KeyDilution == 0 {
			return nil, fmt.Errorf("online mode requires: keydilution, as reported for the participation key")
		}
	}

	// Build signing context (handles auth address lookup for rekeyed accounts)
	signingCtx, err := e.BuildSigningContext(ctx, params.Account)
	if err != nil {
		return nil, err
	}

	// Get suggested params
	sp, err := e.getSuggestedParamsWithFee(ctx, 0, false)
	if err != nil {
		return nil, err
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

	// Set incentive fee if eligible.
	// 2 ALGO is the protocol-defined minimum fee for incentive eligibility (AVM v11+).
	const incentiveFeeMicroAlgos = 2_000_000
	if params.IncentiveEligible {
		txnObj.Fee = types.MicroAlgos(incentiveFeeMicroAlgos)
	}

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: signingCtx,
		LsigArgs:       params.LsigArgs,
	}, nil
}

func (e *Engine) GetIncentiveEligibility(ctx context.Context, address string) (bool, error) {
	if e.AlgodClient == nil {
		return false, ErrNoAlgodClient
	}

	acctInfo, err := e.AlgodClient.AccountInformation(address).Do(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get account info: %w", err)
	}

	return acctInfo.IncentiveEligible, nil
}
