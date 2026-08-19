// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package harness provides shared test utilities for integration tests
package harness

import (
	"context"
	"fmt"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// FundingAccount represents a test funding account that provides ALGO and assets for tests
type FundingAccount struct {
	Address     string
	MinALGO     uint64 // spendable microAlgos required above protocol minimum balance
	MinUSDC     uint64 // USDC base units required (optional)
	USDCAssetID uint64 // Asset ID for USDC on testnet
}

// NewFundingAccount creates a funding account checker from the native Falcon
// TEST_FUNDING_MNEMONIC. The funding address is always derived from the
// mnemonic; there is no separate address selector.
func NewFundingAccount() (*FundingAccount, error) {
	mn := os.Getenv("TEST_FUNDING_MNEMONIC")
	if mn == "" {
		return nil, fmt.Errorf("TEST_FUNDING_MNEMONIC environment variable not set")
	}
	addr, err := NativeFundingAddressFromMnemonic(mn)
	if err != nil {
		return nil, fmt.Errorf("invalid native Falcon TEST_FUNDING_MNEMONIC: %w", err)
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

	// Check spendable ALGO balance. Raw account balance is not enough because
	// app/asset opt-ins raise the protocol minimum balance.
	var spendable uint64
	if acctInfo.Amount > acctInfo.MinBalance {
		spendable = acctInfo.Amount - acctInfo.MinBalance
	}
	if spendable < f.MinALGO {
		return fmt.Errorf("insufficient spendable ALGO in funding account %s: balance %d microAlgos, min-balance %d, spendable %d, need %d spendable microAlgos (%.6f ALGO)",
			f.Address, acctInfo.Amount, acctInfo.MinBalance, spendable, f.MinALGO, float64(f.MinALGO)/1_000_000)
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
