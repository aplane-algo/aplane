// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// ASA (Algorand Standard Asset) transfer operations

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/transaction"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
)

// findAssetHolding searches an account's assets for a specific asset ID.
// Returns the amount and true if found, or 0 and false if not opted in.
func findAssetHolding(assets []models.AssetHolding, assetID uint64) (uint64, bool) {
	for _, asset := range assets {
		if asset.AssetId == assetID {
			return asset.Amount, true
		}
	}
	return 0, false
}

// SendASAParams contains parameters for sending ASA tokens.
// All addresses must be resolved 58-character Algorand addresses.
type SendASAParams struct {
	From       string            // Resolved sender address (58-char)
	To         string            // Resolved receiver address (58-char)
	AssetID    uint64            // Resolved asset ID
	Amount     uint64            // Amount in base units (accounting for decimals)
	Note       string            // Optional note
	Fee        uint64            // Optional custom fee in microAlgos
	UseFlatFee bool              // If true, use Fee as flat fee
	LsigArgs   map[string][]byte // Optional LogicSig arguments for generic LogicSigs (e.g., HTLC preimage)
}

// OptInParams contains parameters for ASA opt-in.
// Address must be resolved 58-character Algorand address.
type OptInParams struct {
	Account    string // Resolved address (58-char)
	AssetID    uint64 // Resolved asset ID
	Fee        uint64 // Optional custom fee in microAlgos
	UseFlatFee bool   // If true, use Fee as flat fee
}

// OptOutParams contains parameters for opting out of an ASA.
// All addresses must be resolved 58-character Algorand addresses.
type OptOutParams struct {
	Account    string // Account opting out (58-char)
	AssetID    uint64 // Asset ID to opt out of
	CloseTo    string // Address to receive remaining balance (optional if balance is 0)
	Fee        uint64 // Optional custom fee in microAlgos
	UseFlatFee bool   // If true, use Fee as flat fee
}

// OptOutCheckResult contains validation results for an opt-out operation.
type OptOutCheckResult struct {
	AssetBalance      uint64 // Current balance of the asset
	IsOptedIn         bool   // True if account is opted into the asset
	CloseToOptedIn    bool   // True if close-to address is opted in (when balance > 0)
	NeedsCloseTo      bool   // True if balance > 0 and close-to is required
	UsingImplicitSelf bool   // True if using sender as close-to (balance = 0)
}

func (e *Engine) PrepareASATransferWithContext(ctx context.Context, params SendASAParams) (*TransactionPrepResult, *BalanceCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}

	// Get ASA info for decimals
	asaInfo, err := e.GetASAInfoWithContext(ctx, params.AssetID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ASA info: %w", err)
	}

	// Build signing context (handles auth address lookup for rekeyed accounts)
	signingCtx, err := e.BuildSigningContextWithContext(ctx, params.From)
	if err != nil {
		return nil, nil, err
	}

	// Check balances
	balanceCheck, err := e.checkASABalancesWithContext(ctx, params.From, params.To, params.AssetID, params.Amount)
	if err != nil {
		return nil, nil, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFeeWithContext(ctx, params.Fee, params.UseFlatFee)
	if err != nil {
		return nil, nil, err
	}

	// Create transaction
	txnObj, err := transaction.MakeAssetTransferTxn(
		params.From,
		params.To,
		params.Amount,
		[]byte(params.Note),
		sp,
		"",
		params.AssetID,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ASA transfer transaction: %w", err)
	}

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: signingCtx,
		AssetInfo:      asaInfo,
		AmountInUnits:  params.Amount,
		LsigArgs:       params.LsigArgs,
	}, balanceCheck, nil
}

func (e *Engine) checkASABalancesWithContext(ctx context.Context, fromAddr, toAddr string, asaID uint64, amountUnits uint64) (*BalanceCheckResult, error) {
	result := &BalanceCheckResult{}

	// Get sender account info
	senderAcct, err := e.AlgodClient.AccountInformation(fromAddr).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sender account info: %w", err)
	}

	// Find sender's ASA balance
	senderASABalance, senderHasAsset := findAssetHolding(senderAcct.Assets, asaID)

	if !senderHasAsset {
		return nil, fmt.Errorf("sender is not opted into asset %d", asaID)
	}

	result.SenderBalance = float64(senderASABalance)
	result.RequiredAmount = float64(amountUnits)
	result.SufficientFunds = senderASABalance >= amountUnits

	// Check receiver is opted in
	receiverAcct, err := e.AlgodClient.AccountInformation(toAddr).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get receiver account info: %w", err)
	}

	_, result.ReceiverOptedIn = findAssetHolding(receiverAcct.Assets, asaID)

	return result, nil
}

func (e *Engine) PrepareOptInWithContext(ctx context.Context, params OptInParams) (*TransactionPrepResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Get ASA info
	asaInfo, err := e.GetASAInfoWithContext(ctx, params.AssetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ASA info: %w", err)
	}

	// Build signing context (handles auth address lookup for rekeyed accounts)
	signingCtx, err := e.BuildSigningContextWithContext(ctx, params.Account)
	if err != nil {
		return nil, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFeeWithContext(ctx, params.Fee, params.UseFlatFee)
	if err != nil {
		return nil, err
	}

	// Create opt-in transaction (0-amount transfer to self)
	txnObj, err := transaction.MakeAssetTransferTxn(
		params.Account,
		params.Account, // To self
		0,              // 0 amount
		nil,            // No note
		sp,
		"",
		params.AssetID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create opt-in transaction: %w", err)
	}

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: signingCtx,
		AssetInfo:      asaInfo,
	}, nil
}

func (e *Engine) PrepareOptOutWithContext(ctx context.Context, params OptOutParams) (*TransactionPrepResult, *OptOutCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}

	checkResult := &OptOutCheckResult{}

	// Get account info to check asset balance
	acctInfo, err := e.AlgodClient.AccountInformation(params.Account).Do(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get account info: %w", err)
	}

	// Find the asset and its balance
	assetBalance, assetFound := findAssetHolding(acctInfo.Assets, params.AssetID)

	if !assetFound {
		return nil, checkResult, fmt.Errorf("account is not opted into asset %d", params.AssetID)
	}

	checkResult.IsOptedIn = true
	checkResult.AssetBalance = assetBalance

	// Determine close-to address
	closeTo := params.CloseTo
	if closeTo == "" {
		if assetBalance > 0 {
			// Balance > 0 requires explicit close-to address
			checkResult.NeedsCloseTo = true
			return nil, checkResult, fmt.Errorf("account holds %d units of asset. Specify 'to <address>' for remainder", assetBalance)
		}
		// Balance is 0, can use self as close-to
		closeTo = params.Account
		checkResult.UsingImplicitSelf = true
	}

	// If balance > 0 and close-to is specified, verify close-to is opted in
	if assetBalance > 0 && closeTo != params.Account {
		closeToAcct, err := e.AlgodClient.AccountInformation(closeTo).Do(ctx)
		if err != nil {
			return nil, checkResult, fmt.Errorf("failed to get close-to account info: %w", err)
		}

		_, closeToOptedIn := findAssetHolding(closeToAcct.Assets, params.AssetID)

		if !closeToOptedIn {
			return nil, checkResult, fmt.Errorf("close-to address is not opted into asset %d", params.AssetID)
		}
		checkResult.CloseToOptedIn = true
	}

	// Build signing context
	signingCtx, err := e.BuildSigningContextWithContext(ctx, params.Account)
	if err != nil {
		return nil, checkResult, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFeeWithContext(ctx, params.Fee, params.UseFlatFee)
	if err != nil {
		return nil, checkResult, err
	}

	// Create opt-out transaction (asset transfer with AssetCloseTo set)
	txnObj, err := transaction.MakeAssetTransferTxn(
		params.Account,
		closeTo, // Receiver (same as close-to for opt-out)
		0,       // 0 amount
		nil,     // No note
		sp,
		closeTo, // AssetCloseTo - closes the asset holding and sends remainder here
		params.AssetID,
	)
	if err != nil {
		return nil, checkResult, fmt.Errorf("failed to create opt-out transaction: %w", err)
	}

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: signingCtx,
	}, checkResult, nil
}
