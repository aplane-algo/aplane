// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Account rekey operations

import (
	"context"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/engine/cosigned"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"

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

func (e *Engine) PrepareRekey(ctx context.Context, params RekeyParams) (*TransactionPrepResult, *RekeyCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}

	checkResult := &RekeyCheckResult{
		IsUnrekey: params.From == params.To,
	}

	if err := refuseZeroAddressTarget("rekey", params.To); err != nil {
		return nil, checkResult, err
	}

	// A rotating account's address is its stage 0 program, a one-time stage
	// key; the signer refuses such a rekey, so refuse it here with the reason
	// before building anything. Any other flow this client cannot route an
	// authorizer through is refused as well.
	if !checkResult.IsUnrekey {
		switch flow := e.signerCacheSigningFlow(params.To); {
		case flow == signerapi.SigningFlowRotating1:
			return nil, checkResult, errors.New(rotatingkey.RekeyTargetRefusal(params.To))
		case !cosigned.CanAuthorizeOtherAccounts(flow):
			return nil, checkResult, fmt.Errorf("cannot rekey to %s: it uses signing flow %q, which this client cannot use as another account's authorizer",
				params.To, flow)
		}
	}

	// Check if target address is itself rekeyed (unless unrekeying)
	if !checkResult.IsUnrekey {
		toAcctInfo, err := e.AlgodClient.AccountInformation(params.To).Do(ctx)
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
	signingCtx, err := e.BuildSigningContext(ctx, params.From)
	if err != nil {
		return nil, checkResult, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFee(ctx, params.Fee, params.UseFlatFee)
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
		SigningContext: signingCtx,
	}, checkResult, nil
}

// refuseZeroAddressTarget refuses the zero address as the target of a rekey
// or a close. In a transaction the zero address in that field means the
// field is absent, so the transaction would be an ordinary payment that
// neither rekeys nor closes, reported back as if it had.
func refuseZeroAddressTarget(action, target string) error {
	if target == types.ZeroAddress.String() {
		return fmt.Errorf("cannot %s to the zero address: the network reads it as no %s at all, so nothing would change", action, action)
	}
	return nil
}
