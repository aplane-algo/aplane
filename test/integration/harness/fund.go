// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
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

// FundMicroAlgos sends an exact amount of microAlgos to a test account.
// Avoids float64 rounding that Fund() is subject to.
func (f *FundTestAccount) FundMicroAlgos(recipientAddress string, amountMicroAlgos uint64) (string, error) {
	sp, err := f.client.SuggestedParams().Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to get suggested params: %w", err)
	}

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

	_, stxnBytes, err := crypto.SignTransaction(f.account.PrivateKey, txn)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	txid, err := f.client.SendRawTransaction(stxnBytes).Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to submit transaction: %w", err)
	}

	return txid, nil
}

// GetAddress returns the funding account address
func (f *FundTestAccount) GetAddress() string {
	return f.account.Address.String()
}

// GetPrivateKey returns the funding account's ed25519 private key.
// Needed for direct SDK signing in test fixture setup (e.g. deploying test apps).
func (f *FundTestAccount) GetPrivateKey() ed25519.PrivateKey {
	return f.account.PrivateKey
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

// FundMicroAlgosAndWait funds an account with an exact microAlgo amount and waits for confirmation.
func (f *FundTestAccount) FundMicroAlgosAndWait(recipientAddress string, amountMicroAlgos uint64) error {
	txid, err := f.FundMicroAlgos(recipientAddress, amountMicroAlgos)
	if err != nil {
		return err
	}

	if err := f.WaitForConfirmation(txid); err != nil {
		return fmt.Errorf("funding transaction %s failed to confirm: %w", txid, err)
	}

	return nil
}
