// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Transaction-related commands:
// - validate: Validate signing capability via 0 ALGO self-send
// - close: Close an account by sending all ALGO to destination
//
// See also:
// - send.go: Send/transfer commands (single, set, atomic)
// - sweep.go: Sweep command for balance consolidation
// - rekey.go: Rekey/unrekey commands

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/cmd/apshell/internal/repl"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/util"
)

// formatAmountWithDecimals formats an amount with specified decimals.
// This is a local wrapper around util.FormatAmountWithDecimals for convenience.
func formatAmountWithDecimals(amountUnits uint64, decimals uint64) string {
	return util.FormatAmountWithDecimals(amountUnits, decimals)
}

// validateWithEngine validates account signing capability using Engine pattern.
// Sends a 0 ALGO self-send transaction to prove we can sign for the account.
// REPL layer: alias/set resolution, UI output
// Engine layer: transaction preparation, signing, submission
func (r *REPLState) validateWithEngine(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: validate <account>\n  Sends a 0 ALGO self-send transaction to validate account signing capability")
	}

	account := args[0]

	// REPL layer: Resolve account (could be alias or @set)
	resolver := r.NewAddressResolver()
	addresses, err := resolver.ResolveList([]string{account})
	if err != nil {
		return fmt.Errorf("failed to resolve account: %w", err)
	}

	if len(addresses) == 0 {
		return fmt.Errorf("no addresses found for '%s'", account)
	}

	isSet := len(account) > 0 && account[0] == '@'
	if isSet {
		util.Debug("validating accounts in set", "count", len(addresses), "set", account)
	}

	// Validate each address sequentially
	successCount := 0
	failCount := 0

	for idx, addr := range addresses {
		if len(addresses) > 1 {
			fmt.Printf("[%d/%d] Validating %s\n", idx+1, len(addresses), r.FormatAddress(addr, ""))
		}

		// Engine layer: Prepare 0 ALGO self-send transaction
		prep, _, err := r.Engine.PreparePayment(engine.SendPaymentParams{
			From:   addr,
			To:     addr, // Self-send
			Amount: 0,    // 0 ALGO
		})
		if err != nil {
			fmt.Printf("  ✗ Failed to prepare: %v\n", err)
			failCount++
			if len(addresses) > 1 {
				fmt.Println()
			}
			continue
		}

		// Engine layer: Sign and submit (always wait for validation)
		result, err := r.Engine.SignAndSubmit(prep, true)
		if err != nil {
			if !errors.Is(err, engine.ErrSimulationFailed) {
				fmt.Printf("  ✗ Failed: %v\n", err)
			}
			failCount++
		} else {
			if !r.Engine.Simulate {
				fmt.Printf("  ✓ Validated successfully (txid: %s)\n", result.TxID)
			}
			successCount++
		}

		if len(addresses) > 1 {
			fmt.Println()
		}
	}

	// REPL layer: Print summary for multiple validations
	if len(addresses) > 1 {
		fmt.Printf("=== Validation Summary ===\n")
		fmt.Printf("Successful: %d/%d\n", successCount, len(addresses))
		fmt.Printf("Failed: %d/%d\n", failCount, len(addresses))

		if failCount > 0 {
			return fmt.Errorf("%d validation(s) failed", failCount)
		}
	} else if failCount > 0 {
		// For single validation, error was already printed inline
		return nil
	}

	return nil
}

// closeWithEngine handles close command using Engine pattern.
// Syntax: close <account> to <destination> [nowait]
// Closes an account by sending all remaining ALGO to the destination.
// Fails if account is online or holds any ASAs.
func (r *REPLState) closeWithEngine(args []string) error {
	// Parse command using dedicated parser
	params, err := repl.ParseCloseCommand(args)
	if err != nil {
		return err
	}

	// REPL Layer: Resolve aliases to addresses
	resolver := r.NewAddressResolver()
	fromAddress, err := resolver.ResolveSingle(params.Account)
	if err != nil {
		return fmt.Errorf("failed to resolve source address '%s': %w", params.Account, err)
	}

	toAddress, err := resolver.ResolveSingle(params.CloseTo)
	if err != nil {
		return fmt.Errorf("failed to resolve destination address '%s': %w", params.CloseTo, err)
	}

	// Prevent closing to self (pointless operation)
	if fromAddress == toAddress {
		return fmt.Errorf("cannot close account to itself")
	}

	// Prepare close transaction via Engine
	prep, checkResult, err := r.Engine.PrepareClose(engine.CloseAccountParams{
		From:     fromAddress,
		CloseTo:  toAddress,
		LsigArgs: params.LsigArgs,
	})
	if err != nil {
		return err
	}

	// Display balance being closed
	balanceAlgo := float64(checkResult.Balance) / 1000000.0
	fmt.Printf("Closing account %s (%.6f ALGO) to %s using %s...\n",
		r.FormatAddress(fromAddress, ""),
		balanceAlgo,
		r.FormatAddress(toAddress, ""),
		prep.SigningContext.DisplayKeyType())

	// Sign and submit
	result, err := r.Engine.SignAndSubmit(prep, params.Wait)
	if err != nil {
		return fmt.Errorf("close failed: %w", err)
	}

	if !r.Engine.Simulate {
		fmt.Printf("Close transaction submitted: %s\n", result.TxID)
	}

	if params.Wait && result.Confirmed {
		fmt.Printf("Account %s closed. %.6f ALGO sent to %s\n",
			r.FormatAddress(fromAddress, ""),
			balanceAlgo,
			r.FormatAddress(toAddress, ""))
	}

	return nil
}
