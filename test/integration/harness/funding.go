// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package harness provides shared test utilities for integration tests
package harness

import (
	"context"
	"fmt"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
)

// FundingAccount represents a test funding account that provides ALGO and assets for tests
type FundingAccount struct {
	Address     string
	MinALGO     uint64 // microAlgos required
	MinUSDC     uint64 // USDC base units required (optional)
	USDCAssetID uint64 // Asset ID for USDC on testnet
}

// NewFundingAccount creates a funding account checker from environment variables
// Accepts either TEST_FUNDING_ACCOUNT (address) or TEST_FUNDING_MNEMONIC (derives address from mnemonic)
func NewFundingAccount() (*FundingAccount, error) {
	addr := os.Getenv("TEST_FUNDING_ACCOUNT")

	// If no address, try to derive from mnemonic
	if addr == "" {
		mn := os.Getenv("TEST_FUNDING_MNEMONIC")
		if mn == "" {
			return nil, fmt.Errorf("neither TEST_FUNDING_ACCOUNT nor TEST_FUNDING_MNEMONIC environment variable set")
		}

		// Derive address from mnemonic
		privateKey, err := mnemonic.ToPrivateKey(mn)
		if err != nil {
			return nil, fmt.Errorf("invalid TEST_FUNDING_MNEMONIC: %w", err)
		}

		// Generate address from private key
		address, err := crypto.GenerateAddressFromSK(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate address from mnemonic: %w", err)
		}
		addr = address.String()
	}

	return &FundingAccount{
		Address:     addr,
		MinALGO:     1_000_000, // 1 ALGO minimum
		MinUSDC:     0,         // No USDC required by default
		USDCAssetID: 10458941,  // USDC on testnet
	}, nil
}

// EnsureFunded checks that the funding account has sufficient balance
func (f *FundingAccount) EnsureFunded(client *algod.Client) error {
	if f.Address == "" {
		return fmt.Errorf("funding account address not set")
	}

	// Get account information
	acctInfo, err := client.AccountInformation(f.Address).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to check funding account %s: %w", f.Address, err)
	}

	// Check ALGO balance
	if acctInfo.Amount < f.MinALGO {
		return fmt.Errorf("insufficient ALGO in funding account %s: have %d microAlgos, need %d microAlgos (%.6f ALGO)",
			f.Address, acctInfo.Amount, f.MinALGO, float64(f.MinALGO)/1_000_000)
	}

	// Check USDC balance if required
	if f.MinUSDC > 0 && f.USDCAssetID > 0 {
		var usdcBalance uint64
		for _, asset := range acctInfo.Assets {
			if asset.AssetId == f.USDCAssetID {
				usdcBalance = asset.Amount
				break
			}
		}

		if usdcBalance < f.MinUSDC {
			return fmt.Errorf("insufficient USDC in funding account %s: have %d, need %d",
				f.Address, usdcBalance, f.MinUSDC)
		}
	}

	return nil
}

// GetBalance returns the current ALGO balance of the funding account
func (f *FundingAccount) GetBalance(client *algod.Client) (uint64, error) {
	acctInfo, err := client.AccountInformation(f.Address).Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to get balance for %s: %w", f.Address, err)
	}
	return acctInfo.Amount, nil
}

// SetMinimums updates the minimum balance requirements
func (f *FundingAccount) SetMinimums(minALGO, minUSDC uint64) {
	f.MinALGO = minALGO
	f.MinUSDC = minUSDC
}
