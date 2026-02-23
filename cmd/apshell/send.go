// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Send command implementations for ALGO and ASA transfers.
// Supports single, set-based, and atomic transaction groups.

import (
	"fmt"

	"github.com/aplane-algo/aplane/cmd/apshell/internal/repl"
	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/engine"
)

func (r *REPLState) sendWithEngine(args []string) error {
	// REPL Layer: Parse command args
	params, err := repl.ParseSendCommand(args)
	if err != nil {
		return err
	}

	// REPL Layer: Resolve aliases and sets to addresses
	resolver := r.NewAddressResolver()
	fromAddresses, err := resolver.ResolveList(params.FromRaw)
	if err != nil {
		return fmt.Errorf("failed to resolve source addresses: %w", err)
	}
	toAddresses, err := resolver.ResolveList(params.ToRaw)
	if err != nil {
		return fmt.Errorf("failed to resolve destination addresses: %w", err)
	}

	// Validate set combinations - reject many-to-many
	isFromSet := len(fromAddresses) > 1
	isToSet := len(toAddresses) > 1
	if isFromSet && isToSet {
		return fmt.Errorf("cannot have multiple senders AND multiple receivers. Use: 1-to-many, many-to-1, or 1-to-1")
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
	}

	// REPL Layer: Convert amount to base units
	amountUnits, err := algo.ConvertTokenAmountToBaseUnits(params.Amount, decimals)
	if err != nil {
		return fmt.Errorf("failed to convert amount: %w", err)
	}

	// Route to appropriate handler based on atomic flag and set sizes
	if params.Atomic {
		if isFromSet {
			// Multiple senders → single receiver atomic
			fmt.Printf("Building atomic transaction group: %d senders → %s\n",
				len(fromAddresses), r.FormatAddress(toAddresses[0], ""))
			return r.sendAtomicFromMultipleEngine(fromAddresses, toAddresses[0], assetID, amountUnits, decimals, assetName, &params)
		} else if isToSet {
			// Single sender → multiple receivers atomic
			fmt.Printf("Building atomic transaction group: %s → %d receivers\n",
				r.FormatAddress(fromAddresses[0], ""), len(toAddresses))
			return r.sendAtomicToMultipleEngine(fromAddresses[0], toAddresses, assetID, amountUnits, decimals, assetName, &params)
		}
		// Single → single with atomic flag falls through to non-atomic
	}

	// Print set summary for non-atomic multi-sends
	if isFromSet {
		fmt.Printf("Sending from %d addresses to %s\n", len(fromAddresses), r.FormatAddress(toAddresses[0], ""))
	} else if isToSet {
		fmt.Printf("Sending to %d addresses\n", len(toAddresses))
	}

	// Non-atomic: iterate through transactions
	return r.sendNonAtomicEngine(fromAddresses, toAddresses, assetID, amountUnits, decimals, assetName, &params)
}

// sendNonAtomicEngine handles non-atomic sends (loops through each transaction)
func (r *REPLState) sendNonAtomicEngine(fromAddresses, toAddresses []string, assetID, amountUnits, decimals uint64, assetName string, params *repl.TransactionParams) error {
	isFromSet := len(fromAddresses) > 1
	isToSet := len(toAddresses) > 1

	// Determine iteration count
	iterCount := len(toAddresses)
	if len(fromAddresses) > iterCount {
		iterCount = len(fromAddresses)
	}

	var lastErr error
	successCount := 0
	failCount := 0

	for idx := 0; idx < iterCount; idx++ {
		// Determine from/to for this iteration
		fromAddr := fromAddresses[0]
		if isFromSet {
			fromAddr = fromAddresses[idx]
		}
		toAddr := toAddresses[0]
		if isToSet {
			toAddr = toAddresses[idx]
		}

		// Print progress for multi-sends
		if iterCount > 1 {
			if isFromSet {
				fmt.Printf("\n[%d/%d] Sending from %s to %s\n", idx+1, iterCount,
					r.FormatAddress(fromAddr, ""), r.FormatAddress(toAddr, ""))
			} else {
				fmt.Printf("\n[%d/%d] Sending to %s\n", idx+1, iterCount, r.FormatAddress(toAddr, ""))
			}
		}

		// Execute single send via Engine
		err := r.sendSingleEngine(fromAddr, toAddr, assetID, amountUnits, decimals, assetName, params)
		if err != nil {
			fmt.Printf("  ✗ Failed: %v\n", err)
			lastErr = err
			failCount++
		} else {
			successCount++
		}
	}

	// Print summary for multi-sends
	if iterCount > 1 {
		fmt.Printf("\n=== Summary ===\n")
		fmt.Printf("Successful: %d/%d\n", successCount, iterCount)
		if failCount > 0 {
			fmt.Printf("Failed: %d/%d\n", failCount, iterCount)
		}

		// Return error only if all failed
		if failCount > 0 && successCount == 0 {
			return lastErr
		}
	}

	return nil
}

// sendSingleEngine sends a single transaction using Engine
func (r *REPLState) sendSingleEngine(from, to string, assetID, amountUnits, decimals uint64, assetName string, params *repl.TransactionParams) error {
	var prep *engine.TransactionPrepResult
	var balanceCheck *engine.BalanceCheckResult
	var err error

	if assetID == 0 {
		// ALGO transfer
		prep, balanceCheck, err = r.Engine.PreparePayment(engine.SendPaymentParams{
			From:       from,
			To:         to,
			Amount:     amountUnits,
			Note:       params.Note,
			Fee:        params.Fee,
			UseFlatFee: params.UseFlatFee,
			LsigArgs:   params.LsigArgs,
		})
	} else {
		// ASA transfer
		prep, balanceCheck, err = r.Engine.PrepareASATransfer(engine.SendASAParams{
			From:       from,
			To:         to,
			AssetID:    assetID,
			Amount:     amountUnits,
			Note:       params.Note,
			Fee:        params.Fee,
			UseFlatFee: params.UseFlatFee,
			LsigArgs:   params.LsigArgs,
		})
	}

	if err != nil {
		return err
	}

	// Check balance results and warn/error as appropriate (REPL layer - UI)
	if !balanceCheck.SufficientFunds {
		return fmt.Errorf("insufficient balance: have %.6f, need %.6f %s",
			balanceCheck.SenderBalance, balanceCheck.RequiredAmount, assetName)
	}
	if assetID != 0 && !balanceCheck.ReceiverOptedIn {
		return fmt.Errorf("receiver %s is not opted into ASA %d (%s)",
			r.FormatAddress(to, ""), assetID, assetName)
	}
	if assetID == 0 && balanceCheck.NewAccount && amountUnits < 100000 {
		return fmt.Errorf("recipient is a new account and needs at least 0.1 ALGO minimum balance")
	}
	if assetID == 0 && balanceCheck.BelowMinBalance {
		minBalanceAlgo := float64(balanceCheck.MinBalance) / 1000000.0
		remainingAlgo := float64(balanceCheck.RemainingBalance) / 1000000.0
		fmt.Printf("⚠️  Warning: After this transaction, balance will be %.6f ALGO, below minimum balance of %.6f ALGO\n",
			remainingAlgo, minBalanceAlgo)
	}

	// Print status (REPL layer - UI)
	amountStr := formatAmountWithDecimals(amountUnits, decimals)
	fmt.Printf("Sending %s %s from %s to %s using %s...\n",
		amountStr, assetName, r.FormatAddress(from, ""), r.FormatAddress(to, ""), prep.SigningContext.DisplayKeyType())
	if params.Note != "" {
		fmt.Printf("Note: %s\n", params.Note)
	}

	// Sign and submit (Engine layer)
	result, err := r.executeTransaction(prep, params.Wait, "transaction")
	if err != nil {
		return err
	}

	if params.Wait && result.Confirmed {
		fmt.Printf("Confirmed: sent %s %s to %s\n",
			amountStr, assetName, r.FormatAddress(to, ""))
	}

	return nil
}

// sendAtomicToMultipleEngine handles single sender → multiple receivers atomic group
func (r *REPLState) sendAtomicToMultipleEngine(from string, toAddresses []string, assetID, amountUnits, decimals uint64, assetName string, params *repl.TransactionParams) error {
	var prep *engine.AtomicPrepResult
	var err error

	groupParams := engine.AtomicGroupParams{
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
	}

	if assetID == 0 {
		// Build ALGO payment params
		payments := make([]engine.AtomicPaymentParams, len(toAddresses))
		for i, to := range toAddresses {
			payments[i] = engine.AtomicPaymentParams{
				From:   from,
				To:     to,
				Amount: amountUnits,
				Note:   params.Note,
			}
		}

		// Validate balances (Engine layer returns data, REPL layer displays)
		var checks []engine.BalanceCheckResult
		checks, err = r.Engine.ValidateAtomicPayments(payments, params.Fee)
		if err != nil {
			return err
		}
		// For single sender, just check first result (all same sender)
		if !checks[0].SufficientFunds {
			totalNeeded := float64(amountUnits*uint64(len(toAddresses))) / 1000000.0
			return fmt.Errorf("insufficient balance: have %.6f ALGO, need %.6f ALGO for %d payments",
				checks[0].SenderBalance, totalNeeded, len(toAddresses))
		}
		fmt.Printf("Sender has %.6f ALGO ✓\n", checks[0].SenderBalance)

		// Check receiver minimum balances
		for i, check := range checks {
			if check.NewAccount && amountUnits < 100000 {
				return fmt.Errorf("receiver %d (%s) is a new account and needs at least 0.1 ALGO",
					i+1, r.FormatAddress(toAddresses[i], ""))
			}
		}

		prep, err = r.Engine.PrepareAtomicPayments(payments, groupParams)
	} else {
		// Build ASA transfer params
		transfers := make([]engine.AtomicASAParams, len(toAddresses))
		for i, to := range toAddresses {
			transfers[i] = engine.AtomicASAParams{
				From:    from,
				To:      to,
				AssetID: assetID,
				Amount:  amountUnits,
				Note:    params.Note,
			}
		}

		// Validate balances and opt-ins
		var checks []engine.BalanceCheckResult
		checks, err = r.Engine.ValidateAtomicASATransfers(transfers)
		if err != nil {
			return err
		}
		// Check sender balance (all same sender)
		totalNeeded := float64(amountUnits * uint64(len(toAddresses)))
		if checks[0].SenderBalance < totalNeeded {
			return fmt.Errorf("insufficient balance: have %.0f %s, need %.0f %s",
				checks[0].SenderBalance, assetName, totalNeeded, assetName)
		}
		fmt.Printf("Sender has %.0f %s ✓\n", checks[0].SenderBalance, assetName)

		// Check all receivers are opted in
		for i, check := range checks {
			if !check.ReceiverOptedIn {
				return fmt.Errorf("receiver %d (%s) is not opted into ASA %d (%s)",
					i+1, r.FormatAddress(toAddresses[i], ""), assetID, assetName)
			}
		}
		fmt.Printf("All receivers are opted into %s ✓\n", assetName)

		prep, err = r.Engine.PrepareAtomicASATransfers(transfers, groupParams)
	}

	if err != nil {
		return err
	}

	// Display transaction summary (REPL layer - UI)
	amountStr := formatAmountWithDecimals(amountUnits, decimals)
	fmt.Printf("\nAtomic transaction group (%d transactions):\n", len(toAddresses))
	for i, to := range toAddresses {
		fmt.Printf("  %d. Send %s %s to %s\n", i+1, amountStr, assetName, r.FormatAddress(to, ""))
	}
	fmt.Println()

	// Sign and submit (Engine layer)
	result, err := r.Engine.SignAndSubmitAtomic(prep, params.Wait)
	if err != nil {
		return fmt.Errorf("atomic transaction group failed: %w", err)
	}

	r.printAtomicGroupResult(result)
	return nil
}

// sendAtomicFromMultipleEngine handles multiple senders → single receiver atomic group
func (r *REPLState) sendAtomicFromMultipleEngine(fromAddresses []string, to string, assetID, amountUnits, decimals uint64, assetName string, params *repl.TransactionParams) error {
	var prep *engine.AtomicPrepResult
	var err error

	groupParams := engine.AtomicGroupParams{
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
	}

	if assetID == 0 {
		// Build ALGO payment params
		payments := make([]engine.AtomicPaymentParams, len(fromAddresses))
		for i, from := range fromAddresses {
			payments[i] = engine.AtomicPaymentParams{
				From:   from,
				To:     to,
				Amount: amountUnits,
				Note:   params.Note,
			}
		}

		// Validate balances
		var checks []engine.BalanceCheckResult
		checks, err = r.Engine.ValidateAtomicPayments(payments, params.Fee)
		if err != nil {
			return err
		}
		for i, check := range checks {
			if !check.SufficientFunds {
				return fmt.Errorf("sender %d (%s) has insufficient balance: have %.6f ALGO, need %.6f ALGO",
					i+1, r.FormatAddress(fromAddresses[i], ""), check.SenderBalance, check.RequiredAmount)
			}
			fmt.Printf("  Sender %d: %.6f ALGO ✓\n", i+1, check.SenderBalance)
		}

		// Check receiver minimum balance (only need to check once)
		if checks[0].NewAccount && amountUnits < 100000 {
			return fmt.Errorf("receiver (%s) is a new account and needs at least 0.1 ALGO",
				r.FormatAddress(to, ""))
		}

		prep, err = r.Engine.PrepareAtomicPayments(payments, groupParams)
	} else {
		// Build ASA transfer params
		transfers := make([]engine.AtomicASAParams, len(fromAddresses))
		for i, from := range fromAddresses {
			transfers[i] = engine.AtomicASAParams{
				From:    from,
				To:      to,
				AssetID: assetID,
				Amount:  amountUnits,
				Note:    params.Note,
			}
		}

		// Validate balances and opt-ins
		var checks []engine.BalanceCheckResult
		checks, err = r.Engine.ValidateAtomicASATransfers(transfers)
		if err != nil {
			return err
		}
		for i, check := range checks {
			if !check.SufficientFunds {
				return fmt.Errorf("sender %d (%s) has insufficient %s: have %.0f, need %.0f",
					i+1, r.FormatAddress(fromAddresses[i], ""), assetName, check.SenderBalance, check.RequiredAmount)
			}
			fmt.Printf("  Sender %d: %.0f %s ✓\n", i+1, check.SenderBalance, assetName)
		}

		// Check receiver is opted in (only need to check first, all same receiver)
		if !checks[0].ReceiverOptedIn {
			return fmt.Errorf("receiver (%s) is not opted into ASA %d (%s)",
				r.FormatAddress(to, ""), assetID, assetName)
		}
		fmt.Printf("Receiver is opted into %s ✓\n", assetName)

		prep, err = r.Engine.PrepareAtomicASATransfers(transfers, groupParams)
	}

	if err != nil {
		return err
	}

	// Display transaction summary (REPL layer - UI)
	amountStr := formatAmountWithDecimals(amountUnits, decimals)
	fmt.Printf("\nAtomic transaction group (%d transactions):\n", len(fromAddresses))
	for i, from := range fromAddresses {
		fmt.Printf("  %d. %s sends %s %s to %s\n",
			i+1, r.FormatAddress(from, ""), amountStr, assetName, r.FormatAddress(to, ""))
	}
	// Calculate total using proper decimals
	totalUnits := amountUnits * uint64(len(fromAddresses))
	totalStr := formatAmountWithDecimals(totalUnits, decimals)
	fmt.Printf("Total received by %s: %s %s\n", r.FormatAddress(to, ""), totalStr, assetName)
	fmt.Println()

	// Sign and submit (Engine layer)
	result, err := r.Engine.SignAndSubmitAtomic(prep, params.Wait)
	if err != nil {
		return fmt.Errorf("atomic transaction group failed: %w", err)
	}

	r.printAtomicGroupResult(result)
	return nil
}
