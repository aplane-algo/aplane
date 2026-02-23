// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package harness

import (
	"context"
	"fmt"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
)

// FundTestAccount funds a test account from the funding account using SDK directly
type FundTestAccount struct {
	client  *algod.Client
	account crypto.Account
}

// NewFundTestAccount creates a funding helper from mnemonic
func NewFundTestAccount(client *algod.Client) (*FundTestAccount, error) {
	// Get mnemonic from environment
	mnemonicStr := os.Getenv("TEST_FUNDING_MNEMONIC")
	if mnemonicStr == "" {
		// If no mnemonic, return nil (tests will skip funding)
		return nil, fmt.Errorf("TEST_FUNDING_MNEMONIC not set")
	}

	// Convert mnemonic to account
	privateKey, err := mnemonic.ToPrivateKey(mnemonicStr)
	if err != nil {
		return nil, fmt.Errorf("invalid funding mnemonic: %w", err)
	}

	account, err := crypto.AccountFromPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create account from private key: %w", err)
	}

	return &FundTestAccount{
		client:  client,
		account: account,
	}, nil
}

// Fund sends ALGO to a test account
func (f *FundTestAccount) Fund(recipientAddress string, amountAlgo float64) (string, error) {
	// Get suggested params
	sp, err := f.client.SuggestedParams().Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to get suggested params: %w", err)
	}

	// Convert ALGO to microAlgos
	amountMicroAlgos := uint64(amountAlgo * 1_000_000)

	// Create payment transaction
	txn, err := transaction.MakePaymentTxn(
		f.account.Address.String(),
		recipientAddress,
		amountMicroAlgos,
		nil, // note
		"",  // close remainder to
		sp,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create payment transaction: %w", err)
	}

	// Sign transaction
	_, stxn, err := crypto.SignTransaction(f.account.PrivateKey, txn)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Encode and submit transaction
	rawTxn := msgpack.Encode(stxn)
	txid, err := f.client.SendRawTransaction(rawTxn).Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to submit transaction: %w", err)
	}

	return txid, nil
}

// GetAddress returns the funding account address
func (f *FundTestAccount) GetAddress() string {
	return f.account.Address.String()
}

// WaitForConfirmation waits for a transaction to be confirmed
func (f *FundTestAccount) WaitForConfirmation(txid string) error {
	status, err := f.client.Status().Do(context.Background())
	if err != nil {
		return err
	}

	lastRound := status.LastRound
	for {
		txInfo, _, err := f.client.PendingTransactionInformation(txid).Do(context.Background())
		if err != nil {
			return err
		}

		if txInfo.ConfirmedRound > 0 {
			return nil // Transaction confirmed
		}

		// Wait for next round
		status, err = f.client.StatusAfterBlock(lastRound).Do(context.Background())
		if err != nil {
			return err
		}
		lastRound = status.LastRound
	}
}

// FundAndWait funds an account and waits for confirmation
func (f *FundTestAccount) FundAndWait(recipientAddress string, amountAlgo float64) error {
	txid, err := f.Fund(recipientAddress, amountAlgo)
	if err != nil {
		return err
	}

	if err := f.WaitForConfirmation(txid); err != nil {
		return fmt.Errorf("funding transaction %s failed to confirm: %w", txid, err)
	}

	return nil
}
