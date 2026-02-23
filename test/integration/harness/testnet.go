// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package harness

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestnetConfig holds testnet connection configuration
type TestnetConfig struct {
	AlgodURL   string
	AlgodToken string
	Client     *algod.Client
}

// NewTestnetConfig creates a new testnet configuration
func NewTestnetConfig() (*TestnetConfig, error) {
	// Use environment variables or defaults
	algodURL := os.Getenv("ALGOD_URL")
	if algodURL == "" {
		algodURL = "https://testnet-api.algonode.cloud"
	}

	algodToken := os.Getenv("ALGOD_TOKEN")
	// AlgoNode doesn't require a token

	// Create client
	client, err := algod.MakeClient(algodURL, algodToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create algod client: %w", err)
	}

	// Test connection
	_, err = client.Status().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to algod: %w", err)
	}

	return &TestnetConfig{
		AlgodURL:   algodURL,
		AlgodToken: algodToken,
		Client:     client,
	}, nil
}

// GetSuggestedParams gets the current suggested parameters
func (tc *TestnetConfig) GetSuggestedParams() (types.SuggestedParams, error) {
	sp, err := tc.Client.SuggestedParams().Do(context.Background())
	if err != nil {
		return types.SuggestedParams{}, fmt.Errorf("failed to get suggested params: %w", err)
	}
	return sp, nil
}

// WaitForConfirmation waits for a transaction to be confirmed
func (tc *TestnetConfig) WaitForConfirmation(txid string, maxRounds uint64) (uint64, error) {
	ctx := context.Background()

	// Get initial status
	status, err := tc.Client.Status().Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get status: %w", err)
	}

	startRound := status.LastRound
	currentRound := startRound

	for currentRound < startRound+maxRounds {
		// Check if transaction is confirmed
		txInfo, _, err := tc.Client.PendingTransactionInformation(txid).Do(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to get transaction info: %w", err)
		}

		if txInfo.ConfirmedRound > 0 {
			// Transaction confirmed
			return txInfo.ConfirmedRound, nil
		}

		// Wait for next round
		status, err = tc.Client.StatusAfterBlock(currentRound).Do(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to wait for round: %w", err)
		}
		currentRound = status.LastRound
	}

	return 0, fmt.Errorf("transaction not confirmed after %d rounds", maxRounds)
}

// SubmitTransaction submits a signed transaction to the network
func (tc *TestnetConfig) SubmitTransaction(stxn types.SignedTxn) (string, error) {
	rawTxn := msgpack.Encode(stxn)
	txid, err := tc.Client.SendRawTransaction(rawTxn).Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to submit transaction: %w", err)
	}
	return txid, nil
}

// SubmitTransactionGroup submits a group of signed transactions
func (tc *TestnetConfig) SubmitTransactionGroup(stxns []types.SignedTxn) ([]string, error) {
	// Convert to raw bytes
	var rawTxns []byte
	for _, stxn := range stxns {
		rawTxns = append(rawTxns, msgpack.Encode(stxn)...)
	}

	// Submit as group
	_, err := tc.Client.SendRawTransaction(rawTxns).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to submit transaction group: %w", err)
	}

	// Extract transaction IDs
	var txids []string
	for _, stxn := range stxns {
		txid := crypto.GetTxID(stxn.Txn)
		txids = append(txids, txid)
	}

	return txids, nil
}

// GetAccountInfo gets information for an account
func (tc *TestnetConfig) GetAccountInfo(address string) (uint64, error) {
	acct, err := tc.Client.AccountInformation(address).Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to get account info: %w", err)
	}
	return acct.Amount, nil
}

// AssetInfo holds basic asset information
type AssetInfo struct {
	AssetID  uint64
	Name     string
	UnitName string
	Total    uint64
	Decimals uint64
	Creator  string
	Manager  string
}

// GetAssetInfo gets information for an asset
func (tc *TestnetConfig) GetAssetInfo(assetID uint64) (*AssetInfo, error) {
	asset, err := tc.Client.GetAssetByID(assetID).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get asset info: %w", err)
	}
	return &AssetInfo{
		AssetID:  assetID,
		Name:     asset.Params.Name,
		UnitName: asset.Params.UnitName,
		Total:    asset.Params.Total,
		Decimals: asset.Params.Decimals,
		Creator:  asset.Params.Creator,
		Manager:  asset.Params.Manager,
	}, nil
}

// WaitForNextRound waits for the next block round
func (tc *TestnetConfig) WaitForNextRound() error {
	status, err := tc.Client.Status().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	_, err = tc.Client.StatusAfterBlock(status.LastRound).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to wait for next round: %w", err)
	}

	return nil
}

// TransactionHelper provides utilities for building test transactions
type TransactionHelper struct {
	testnet *TestnetConfig
}

// NewTransactionHelper creates a new transaction helper
func NewTransactionHelper(testnet *TestnetConfig) *TransactionHelper {
	return &TransactionHelper{
		testnet: testnet,
	}
}

// CreatePayment creates a payment transaction
func (th *TransactionHelper) CreatePayment(from, to string, amount uint64) (types.Transaction, error) {
	sp, err := th.testnet.GetSuggestedParams()
	if err != nil {
		return types.Transaction{}, err
	}

	txn, err := transaction.MakePaymentTxn(from, to, amount, nil, "", sp)
	if err != nil {
		return types.Transaction{}, fmt.Errorf("failed to create payment: %w", err)
	}

	return txn, nil
}

// CreateAssetTransfer creates an asset transfer transaction
func (th *TransactionHelper) CreateAssetTransfer(from, to string, assetID, amount uint64) (types.Transaction, error) {
	sp, err := th.testnet.GetSuggestedParams()
	if err != nil {
		return types.Transaction{}, err
	}

	txn, err := transaction.MakeAssetTransferTxn(from, to, amount, nil, sp, "", assetID)
	if err != nil {
		return types.Transaction{}, fmt.Errorf("failed to create asset transfer: %w", err)
	}

	return txn, nil
}

// TestTimeout provides standard timeouts for integration tests
type TestTimeout struct {
	ProcessStart time.Duration
	Transaction  time.Duration
	Confirmation time.Duration
}

// DefaultTimeouts returns default timeout values
func DefaultTimeouts() TestTimeout {
	return TestTimeout{
		ProcessStart: 10 * time.Second,
		Transaction:  30 * time.Second,
		Confirmation: 20 * time.Second,
	}
}

// RetryConfig configures retry behavior for flaky operations
type RetryConfig struct {
	MaxAttempts int
	Delay       time.Duration
	BackoffRate float64
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		Delay:       1 * time.Second,
		BackoffRate: 2.0,
	}
}

// RetryOperation retries an operation with exponential backoff
func RetryOperation(config RetryConfig, operation func() error) error {
	var lastErr error
	delay := config.Delay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		if err := operation(); err == nil {
			return nil
		} else {
			lastErr = err
			if attempt < config.MaxAttempts {
				time.Sleep(delay)
				delay = time.Duration(float64(delay) * config.BackoffRate)
			}
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}
