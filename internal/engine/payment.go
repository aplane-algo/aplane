// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

// ALGO payment transaction methods

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
)

// SendPaymentParams contains parameters for sending ALGO.
// All addresses must be resolved 58-character Algorand addresses.
type SendPaymentParams struct {
	From       string            // Resolved sender address (58-char)
	To         string            // Resolved receiver address (58-char)
	Amount     uint64            // Amount in microAlgos
	Note       string            // Optional note
	Fee        uint64            // Optional custom fee in microAlgos
	UseFlatFee bool              // If true, use Fee as flat fee
	Close      bool              // If true, close account and send remaining balance to To
	LsigArgs   map[string][]byte // Optional LogicSig arguments for generic LogicSigs (e.g., hashlock preimage)
}

// PreparePayment validates and prepares an ALGO payment transaction.
// Addresses must be pre-resolved (no aliases).
func (e *Engine) PreparePayment(params SendPaymentParams) (*TransactionPrepResult, *BalanceCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}

	// Build signing context (handles auth address lookup for rekeyed accounts)
	ctx, err := e.BuildSigningContext(params.From)
	if err != nil {
		return nil, nil, err
	}

	// Check balances
	balanceCheck, err := e.checkPaymentBalances(params.From, params.To, params.Amount, params.Fee, params.UseFlatFee)
	if err != nil {
		return nil, nil, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFee(params.Fee, params.UseFlatFee)
	if err != nil {
		return nil, nil, err
	}

	// Create transaction
	closeRemainderTo := ""
	if params.Close {
		closeRemainderTo = params.To
	}
	txnObj, err := transaction.MakePaymentTxn(
		params.From,
		params.To,
		params.Amount,
		[]byte(params.Note),
		closeRemainderTo,
		sp,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create payment transaction: %w", err)
	}

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: ctx,
		AmountInUnits:  params.Amount,
		LsigArgs:       params.LsigArgs,
	}, balanceCheck, nil
}

// checkPaymentBalances validates balances for an ALGO payment.
// Addresses must be pre-resolved (no aliases).
func (e *Engine) checkPaymentBalances(fromAddr, toAddr string, amountMicro, fee uint64, useFlatFee bool) (*BalanceCheckResult, error) {
	result := &BalanceCheckResult{}

	// Get sender account info
	senderAcct, err := e.AlgodClient.AccountInformation(fromAddr).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get sender account info: %w", err)
	}
	result.SenderBalance = float64(senderAcct.Amount) / 1000000.0

	// Calculate required amount
	txnFee := uint64(1000) // Standard fee
	if useFlatFee && fee > 0 {
		txnFee = fee
	}
	txnFeeAlgo := float64(txnFee) / 1000000.0
	amountAlgo := float64(amountMicro) / 1000000.0
	result.RequiredAmount = amountAlgo + txnFeeAlgo
	result.SufficientFunds = result.SenderBalance >= result.RequiredAmount

	// Check receiver
	receiverAcct, err := e.AlgodClient.AccountInformation(toAddr).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get receiver account info: %w", err)
	}

	result.NewAccount = receiverAcct.Amount == 0
	const minBalanceMicroAlgos uint64 = 100000
	if result.NewAccount && amountMicro < minBalanceMicroAlgos {
		// New account needs at least 0.1 ALGO
		result.SufficientFunds = false
	}

	// Check if sender will be below min balance after tx
	result.MinBalance = senderAcct.MinBalance
	if senderAcct.Amount >= amountMicro+txnFee {
		result.RemainingBalance = senderAcct.Amount - amountMicro - txnFee
		result.BelowMinBalance = result.RemainingBalance < senderAcct.MinBalance
	} else {
		result.BelowMinBalance = true
	}

	result.ReceiverOptedIn = true // Always true for ALGO

	return result, nil
}

// CloseAccountParams contains parameters for closing an account.
// All addresses must be resolved 58-character Algorand addresses.
type CloseAccountParams struct {
	From       string            // Account to close (58-char)
	CloseTo    string            // Address to receive remaining ALGO (58-char)
	Fee        uint64            // Optional custom fee in microAlgos
	UseFlatFee bool              // If true, use Fee as flat fee
	LsigArgs   map[string][]byte // Optional LogicSig arguments for generic LogicSigs (e.g., hashlock preimage)
}

// CloseAccountCheckResult contains validation results for a close operation.
type CloseAccountCheckResult struct {
	Balance      uint64   // Current ALGO balance in microAlgos
	IsOnline     bool     // True if account is online (participating in consensus)
	HasASAs      bool     // True if account holds any ASAs
	ASACount     int      // Number of ASAs held
	ASAIDs       []uint64 // List of ASA IDs held (for error reporting)
	CloseToValid bool     // True if close-to address is valid
}

// PrepareClose validates and prepares an account close transaction.
// Addresses must be pre-resolved (no aliases).
// Returns error if account is online or has ASAs.
func (e *Engine) PrepareClose(params CloseAccountParams) (*TransactionPrepResult, *CloseAccountCheckResult, error) {
	if e.AlgodClient == nil {
		return nil, nil, ErrNoAlgodClient
	}

	checkResult := &CloseAccountCheckResult{}

	// Get account info to check status
	acctInfo, err := e.AlgodClient.AccountInformation(params.From).Do(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get account info: %w", err)
	}

	checkResult.Balance = acctInfo.Amount

	// Check if account is already closed (zero balance)
	if acctInfo.Amount == 0 {
		return nil, checkResult, fmt.Errorf("account is already closed (zero balance)")
	}

	// Check if account is online (participating in consensus)
	if acctInfo.Status == "Online" {
		checkResult.IsOnline = true
		return nil, checkResult, fmt.Errorf("cannot close account: account is online (participating in consensus). Use 'keyreg %s offline' first", params.From)
	}

	// Check if account has any ASAs
	if len(acctInfo.Assets) > 0 {
		checkResult.HasASAs = true
		checkResult.ASACount = len(acctInfo.Assets)
		checkResult.ASAIDs = make([]uint64, len(acctInfo.Assets))
		for i, asset := range acctInfo.Assets {
			checkResult.ASAIDs[i] = asset.AssetId
		}
		return nil, checkResult, fmt.Errorf("cannot close account: account holds %d ASA(s). Opt out or transfer them first", len(acctInfo.Assets))
	}

	// Validate close-to address exists (don't close to a non-existent account)
	closeToAcct, err := e.AlgodClient.AccountInformation(params.CloseTo).Do(context.Background())
	if err != nil {
		return nil, checkResult, fmt.Errorf("failed to get close-to account info: %w", err)
	}
	checkResult.CloseToValid = closeToAcct.Amount > 0 || params.CloseTo == params.From

	// Build signing context (handles auth address lookup for rekeyed accounts)
	ctx, err := e.BuildSigningContext(params.From)
	if err != nil {
		return nil, checkResult, err
	}

	// Get suggested params with fee settings
	sp, err := e.getSuggestedParamsWithFee(params.Fee, params.UseFlatFee)
	if err != nil {
		return nil, checkResult, err
	}

	// Create close transaction (payment with CloseRemainderTo set)
	txnObj, err := transaction.MakePaymentTxn(
		params.From,
		params.CloseTo, // Send to close-to address
		0,              // 0 amount (CloseRemainderTo handles the transfer)
		nil,            // No note
		params.CloseTo, // CloseRemainderTo - sends all remaining ALGO here
		sp,
	)
	if err != nil {
		return nil, checkResult, fmt.Errorf("failed to create close transaction: %w", err)
	}

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: ctx,
		LsigArgs:       params.LsigArgs,
	}, checkResult, nil
}
