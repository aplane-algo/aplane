// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

// ASA (Algorand Standard Asset) transfer operations

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
)

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
	LsigArgs   map[string][]byte // Optional LogicSig arguments for generic LogicSigs (e.g., hashlock preimage)
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

// PrepareASATransfer validates and prepares an ASA transfer transaction.
// Addresses must be pre-resolved (no aliases). AssetID must be pre-resolved.
func (e *Engine) PrepareASATransfer(params SendASAParams) (*TransactionPrepResult, *BalanceCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}

	// Get ASA info for decimals
	asaInfo, err := e.GetASAInfo(params.AssetID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ASA info: %w", err)
	}

	// Build signing context (handles auth address lookup for rekeyed accounts)
	ctx, err := e.BuildSigningContext(params.From)
	if err != nil {
		return nil, nil, err
	}

	// Check balances
	balanceCheck, err := e.checkASABalances(params.From, params.To, params.AssetID, params.Amount)
	if err != nil {
		return nil, nil, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFee(params.Fee, params.UseFlatFee)
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
		SigningContext: ctx,
		AssetInfo:      asaInfo,
		AmountInUnits:  params.Amount,
		LsigArgs:       params.LsigArgs,
	}, balanceCheck, nil
}

// checkASABalances validates balances for an ASA transfer.
// Addresses must be pre-resolved (no aliases).
func (e *Engine) checkASABalances(fromAddr, toAddr string, asaID uint64, amountUnits uint64) (*BalanceCheckResult, error) {
	result := &BalanceCheckResult{}

	// Get sender account info
	senderAcct, err := e.AlgodClient.AccountInformation(fromAddr).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get sender account info: %w", err)
	}

	// Find sender's ASA balance
	var senderASABalance uint64
	senderHasAsset := false
	for _, asset := range senderAcct.Assets {
		if asset.AssetId == asaID {
			senderASABalance = asset.Amount
			senderHasAsset = true
			break
		}
	}

	if !senderHasAsset {
		return nil, fmt.Errorf("sender is not opted into asset %d", asaID)
	}

	result.SenderBalance = float64(senderASABalance)
	result.RequiredAmount = float64(amountUnits)
	result.SufficientFunds = senderASABalance >= amountUnits

	// Check receiver is opted in
	receiverAcct, err := e.AlgodClient.AccountInformation(toAddr).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get receiver account info: %w", err)
	}

	result.ReceiverOptedIn = false
	for _, asset := range receiverAcct.Assets {
		if asset.AssetId == asaID {
			result.ReceiverOptedIn = true
			break
		}
	}

	return result, nil
}

// PrepareOptIn validates and prepares an ASA opt-in transaction.
// Address must be pre-resolved (no aliases). AssetID must be pre-resolved.
func (e *Engine) PrepareOptIn(params OptInParams) (*TransactionPrepResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Get ASA info
	asaInfo, err := e.GetASAInfo(params.AssetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ASA info: %w", err)
	}

	// Build signing context (handles auth address lookup for rekeyed accounts)
	ctx, err := e.BuildSigningContext(params.Account)
	if err != nil {
		return nil, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFee(params.Fee, params.UseFlatFee)
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
		SigningContext: ctx,
		AssetInfo:      asaInfo,
	}, nil
}

// PrepareOptOut validates and prepares an ASA opt-out transaction.
// Addresses must be pre-resolved (no aliases). AssetID must be pre-resolved.
// If balance is 0 and CloseTo is empty, uses sender as CloseTo.
// If balance > 0 and CloseTo is empty, returns error.
func (e *Engine) PrepareOptOut(params OptOutParams) (*TransactionPrepResult, *OptOutCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}

	checkResult := &OptOutCheckResult{}

	// Get account info to check asset balance
	acctInfo, err := e.AlgodClient.AccountInformation(params.Account).Do(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get account info: %w", err)
	}

	// Find the asset and its balance
	var assetBalance uint64
	assetFound := false
	for _, asset := range acctInfo.Assets {
		if asset.AssetId == params.AssetID {
			assetBalance = asset.Amount
			assetFound = true
			break
		}
	}

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
		closeToAcct, err := e.AlgodClient.AccountInformation(closeTo).Do(context.Background())
		if err != nil {
			return nil, checkResult, fmt.Errorf("failed to get close-to account info: %w", err)
		}

		closeToOptedIn := false
		for _, asset := range closeToAcct.Assets {
			if asset.AssetId == params.AssetID {
				closeToOptedIn = true
				break
			}
		}

		if !closeToOptedIn {
			return nil, checkResult, fmt.Errorf("close-to address is not opted into asset %d", params.AssetID)
		}
		checkResult.CloseToOptedIn = true
	}

	// Build signing context
	ctx, err := e.BuildSigningContext(params.Account)
	if err != nil {
		return nil, checkResult, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFee(params.Fee, params.UseFlatFee)
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
		SigningContext: ctx,
	}, checkResult, nil
}
