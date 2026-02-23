// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Sweep command implementation for consolidating ALGO or ASA balances.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/cmd/apshell/internal/repl"
	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/engine"
)

// sweepWithEngine handles sweep command using Engine pattern with proper layer separation.
func (r *REPLState) sweepWithEngine(args []string) error {
	// REPL Layer: Parse command args
	params, err := repl.ParseSweepCommand(args)
	if err != nil {
		return err
	}

	// REPL Layer: Resolve addresses
	resolver := r.NewAddressResolver()

	// Resolve source addresses (or use all signable accounts if none specified)
	var fromAddresses []string
	if params.FromRaw == nil {
		// No "from" accounts specified, use all signable accounts
		fromAddresses = r.Engine.GetSignableAddresses()
		if len(fromAddresses) == 0 {
			return fmt.Errorf("no signable accounts available. Connect to Signer first or specify accounts with: sweep <asset> from [account1 account2] to <dest>")
		}

		// Display found accounts (REPL layer - UI)
		fmt.Println("No source accounts specified, using all signable accounts...")
		aliasedFrom := make([]string, 0, len(fromAddresses))
		for _, addr := range fromAddresses {
			alias := r.Engine.AliasCache.GetAliasForAddress(addr)
			if alias != "" {
				aliasedFrom = append(aliasedFrom, alias)
			} else {
				aliasedFrom = append(aliasedFrom, addr)
			}
		}
		fmt.Printf("Found %d signable account(s): %s\n", len(fromAddresses), strings.Join(aliasedFrom, ", "))
	} else {
		fromAddresses, err = resolver.ResolveList(params.FromRaw)
		if err != nil {
			return fmt.Errorf("failed to resolve source addresses: %w", err)
		}
	}

	// Resolve destination address
	toAddress, err := resolver.ResolveSingle(params.ToRaw)
	if err != nil {
		return fmt.Errorf("failed to resolve destination address: %w", err)
	}

	// REPL Layer: Resolve ASA reference to ID (0 means ALGO)
	var assetID uint64
	var decimals uint64 = 6 // Default for ALGO
	assetName := "ALGO"
	if params.Asset != "algo" {
		assetID, err = r.Engine.AsaCache.ResolveASAReference(params.Asset, r.Engine.Network)
		if err != nil {
			return fmt.Errorf("failed to resolve ASA '%s': %w", params.Asset, err)
		}
		asaInfo, err := r.Engine.GetASAInfo(assetID)
		if err != nil {
			return fmt.Errorf("failed to get ASA info: %w", err)
		}
		decimals = asaInfo.Decimals
		assetName = asaInfo.UnitName

		// Check receiver is opted in (once for all transfers)
		receiverBalance, err := r.Engine.GetAccountBalanceRaw(toAddress)
		if err != nil {
			return fmt.Errorf("failed to get receiver account info: %w", err)
		}
		receiverOptedIn := false
		for _, asset := range receiverBalance.Assets {
			if asset.AssetID == assetID {
				receiverOptedIn = true
				break
			}
		}
		if !receiverOptedIn {
			return fmt.Errorf("receiver %s is not opted into ASA %d (%s)",
				r.FormatAddress(toAddress, ""), assetID, assetName)
		}
		fmt.Printf("Receiver is opted into %s ✓\n", assetName)
	}

	// REPL Layer: Convert leaving amount to base units
	leavingBaseUnits, err := algo.ConvertTokenAmountToBaseUnits(params.Leaving, decimals)
	if err != nil {
		return fmt.Errorf("failed to convert leaving amount: %w", err)
	}
	leavingFloat, _ := strconv.ParseFloat(params.Leaving, 64)

	// Print sweep header (REPL layer - UI)
	fmt.Printf("\nSweeping %s from %d account(s) to %s", params.Asset, len(fromAddresses), r.FormatAddress(toAddress, ""))
	if leavingFloat > 0 {
		fmt.Printf(" (leaving %s in each)", params.Leaving)
	}
	fmt.Println("\n" + strings.Repeat("=", 60))

	// Track success/failure
	successCount := 0
	failCount := 0
	var lastTxid string

	// Process each source account
	for i, fromAddress := range fromAddresses {
		fmt.Printf("\n[%d/%d] Processing %s...\n", i+1, len(fromAddresses), r.FormatAddress(fromAddress, ""))

		// Skip if source == destination
		if fromAddress == toAddress {
			fmt.Printf("  - Skipping (source and destination are the same account)\n")
			continue
		}

		// Get account balance via Engine (alias-agnostic)
		balanceResult, err := r.Engine.GetAccountBalanceRaw(fromAddress)
		if err != nil {
			fmt.Printf("  ✗ Failed to get account info: %v\n", err)
			failCount++
			continue
		}

		// Calculate sweep amount
		var balance uint64
		if assetID == 0 {
			// ALGO balance
			balance = balanceResult.AlgoBalance
		} else {
			// ASA balance - find the asset
			found := false
			for _, asset := range balanceResult.Assets {
				if asset.AssetID == assetID {
					balance = asset.Amount
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("  - Account not opted into %s, skipping\n", assetName)
				continue
			}
		}

		// Calculate amount to send
		if balance <= leavingBaseUnits {
			fmt.Printf("  - Balance %d <= leaving amount %d, skipping\n", balance, leavingBaseUnits)
			continue
		}
		amountToSend := balance - leavingBaseUnits

		if amountToSend == 0 {
			fmt.Printf("  - No balance to sweep, skipping\n")
			continue
		}

		// Format amount for display
		amountStr := formatAmountWithDecimals(amountToSend, decimals)

		// Print status (REPL layer - UI)
		fmt.Printf("  Sending %s %s...\n", amountStr, assetName)

		// Prepare and submit transaction via Engine
		var prep *engine.TransactionPrepResult
		if assetID == 0 {
			prep, _, err = r.Engine.PreparePayment(engine.SendPaymentParams{
				From:       fromAddress,
				To:         toAddress,
				Amount:     amountToSend,
				Fee:        params.Fee,
				UseFlatFee: params.UseFlatFee,
			})
		} else {
			prep, _, err = r.Engine.PrepareASATransfer(engine.SendASAParams{
				From:       fromAddress,
				To:         toAddress,
				AssetID:    assetID,
				Amount:     amountToSend,
				Fee:        params.Fee,
				UseFlatFee: params.UseFlatFee,
			})
		}

		if err != nil {
			fmt.Printf("  ✗ Failed to prepare transaction: %v\n", err)
			failCount++
			continue
		}

		// Sign and submit
		result, err := r.Engine.SignAndSubmit(prep, params.Wait)
		if err != nil {
			if !errors.Is(err, engine.ErrSimulationFailed) {
				fmt.Printf("  ✗ Transaction failed: %v\n", err)
			}
			failCount++
			continue
		}

		if !r.Engine.Simulate {
			fmt.Printf("  ✓ Transaction submitted: %s\n", result.TxID)
		}
		lastTxid = result.TxID
		successCount++

		// Confirmation is handled by SignAndSubmit with wait flag
		if params.Wait && result.Confirmed {
			fmt.Printf("  ✓ Confirmed\n")
		}
	}

	// Print summary (REPL layer - UI)
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("Sweep complete: %d succeeded, %d failed\n", successCount, failCount)
	if successCount > 0 {
		fmt.Printf("Last transaction: %s\n", lastTxid)
	}

	if failCount > 0 && successCount == 0 {
		return fmt.Errorf("all %d transaction(s) failed", failCount)
	}

	return nil
}
