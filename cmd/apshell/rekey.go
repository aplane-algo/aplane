// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Rekey command implementations for account rekeying operations.

import (
	"fmt"

	"github.com/aplane-algo/aplane/cmd/apshell/internal/repl"
	"github.com/aplane-algo/aplane/internal/engine"
)

// listRekeys lists all rekeyed accounts from cache.
func (r *REPLState) listRekeys() error {
	fmt.Println("Listing rekeyed accounts (from cache)...")
	fmt.Println()

	foundRekey := false
	processedAddresses := make(map[string]bool)

	addressesToCheck := make(map[string]bool)

	for _, addr := range r.Engine.AliasCache.Aliases {
		addressesToCheck[addr] = true
	}

	for addr := range r.Engine.SignerCache.Keys {
		addressesToCheck[addr] = true
	}

	for addr := range addressesToCheck {
		if processedAddresses[addr] {
			continue
		}
		processedAddresses[addr] = true

		authAddr, exists := r.Engine.AuthCache.GetAuthAddress(addr)

		if !exists {
			continue
		}

		if authAddr != "" && authAddr != addr {
			fmt.Printf("%s\nauth: %s\n\n",
				r.FormatAddress(addr, authAddr),
				r.FormatAddress(authAddr, ""))
			foundRekey = true
		}
	}

	if !foundRekey {
		fmt.Println("No rekeyed accounts found.")
	}

	return nil
}

// rekeyWithEngine handles rekey command using Engine pattern.
// REPL layer: parsing, alias resolution, UI output
// Engine layer: transaction preparation, signing, submission
func (r *REPLState) rekeyWithEngine(args []string) error {
	// Handle special subcommands (list, refresh) - these stay in REPL layer
	if len(args) == 0 {
		return r.listRekeys()
	}
	if args[0] == "refresh" {
		if len(args) != 1 {
			return fmt.Errorf("usage: rekey refresh")
		}
		return r.refreshAuthCache()
	}

	// REPL layer: Parse natural language command
	params, err := repl.ParseRekeyCommand(args, false)
	if err != nil {
		return err
	}

	// REPL layer: Resolve aliases to addresses
	resolver := r.NewAddressResolver()

	fromAddress, err := resolver.ResolveSingle(params.Account)
	if err != nil {
		return fmt.Errorf("failed to resolve from address: %w", err)
	}

	toAddress, err := resolver.ResolveSingle(params.Signer)
	if err != nil {
		return fmt.Errorf("failed to resolve to address: %w", err)
	}

	// Engine layer: Prepare rekey transaction (validates target not rekeyed)
	engineParams := engine.RekeyParams{
		From:       fromAddress,
		To:         toAddress,
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
	}

	prepResult, checkResult, err := r.Engine.PrepareRekey(engineParams)
	if err != nil {
		if checkResult != nil && checkResult.TargetIsRekeyed {
			return fmt.Errorf("cannot rekey to %s because it is itself rekeyed to %s. You must rekey to the final auth address in the chain, or unrekey the target first",
				r.FormatAddress(toAddress, ""), r.FormatAddress(checkResult.TargetAuthAddr, ""))
		}
		return err
	}

	// Engine layer: Check if we can sign for target
	canSignForTarget, isLsig := r.Engine.CanSignForAddress(toAddress)

	// REPL layer: Print appropriate messages
	if canSignForTarget {
		if isLsig {
			fmt.Printf("Rekeying account %s to lsig address %s...\n", r.FormatAddress(fromAddress, ""), r.FormatAddress(toAddress, ""))
		} else {
			fmt.Printf("Rekeying account %s to Ed25519 address %s...\n", r.FormatAddress(fromAddress, ""), r.FormatAddress(toAddress, ""))
		}
	} else {
		fmt.Println("⚠️  WARNING: Rekeying to Address You Cannot Sign For!")
		fmt.Printf("Target address: %s\n", r.FormatAddress(toAddress, ""))
		fmt.Println("\nThis system cannot sign for this target address.")
		fmt.Println("After rekeying, you will NOT be able to sign transactions from this account using this system.")
		fmt.Println("\nYou will need:")
		fmt.Println("  - The private key for the target address, OR")
		fmt.Println("  - Another way to authorize transactions")
		fmt.Println("\nThis operation cannot be easily reversed!")
		fmt.Printf("\nProceeding with rekey to %s...\n", r.FormatAddress(toAddress, ""))
		fmt.Println("(You will be asked to approve at Signer)")
	}
	fmt.Println("WARNING: After this transaction, you must use the new auth address to sign!")

	// Engine layer: Sign and submit
	submitResult, err := r.Engine.SignAndSubmit(prepResult, params.Wait)
	if err != nil {
		return fmt.Errorf("rekey transaction failed: %w", err)
	}

	// REPL layer: Print results
	if !r.Engine.Simulate {
		fmt.Printf("Rekey transaction submitted: %s\n", submitResult.TxID)
	}

	if params.Wait && submitResult.Confirmed {
		// Refresh auth address cache after successful rekey
		_, err = r.Engine.AuthCache.RefreshAuthAddress(r.Engine.AlgodClient, fromAddress, r.Engine.Network)
		if err != nil {
			fmt.Printf("⚠️  Warning: failed to update auth cache: %v\n", err)
		}

		// Print success message
		if checkResult.IsUnrekey {
			fmt.Printf("Account %s is now back to normal (no rekey in effect)\n", r.FormatAddress(fromAddress, ""))
		} else if canSignForTarget {
			if isLsig {
				fmt.Printf("Account %s is now rekeyed to lsig %s\n", r.FormatAddress(fromAddress, ""), r.FormatAddress(toAddress, ""))
			} else {
				fmt.Printf("Account %s is now rekeyed to Ed25519 address %s\n", r.FormatAddress(fromAddress, ""), r.FormatAddress(toAddress, ""))
			}
		} else {
			fmt.Println("\nAccount rekeyed to address you cannot sign for.")
			fmt.Println("Your system can no longer sign transactions for this account.")
			fmt.Println("To regain control, you'll need to sign with the new auth address.")
		}
	} else if !params.Wait {
		if canSignForTarget {
			if isLsig {
				fmt.Printf("\nWhen confirmed, %s will be rekeyed to lsig %s\n", r.FormatAddress(fromAddress, ""), r.FormatAddress(toAddress, ""))
			} else {
				fmt.Printf("\nWhen confirmed, %s will be rekeyed to Ed25519 address %s\n", r.FormatAddress(fromAddress, ""), r.FormatAddress(toAddress, ""))
			}
		} else {
			fmt.Println("\nTarget is an address you cannot sign for - you'll need the new auth address's private key to sign.")
		}
	}

	return nil
}

// unrekeyWithEngine handles unrekey command using Engine pattern.
// unrekey <account> [nowait] - rekeys account back to itself
func (r *REPLState) unrekeyWithEngine(args []string) error {
	// REPL layer: Parse command
	params, err := repl.ParseRekeyCommand(args, true) // true = isUnrekey
	if err != nil {
		return err
	}

	// REPL layer: Resolve alias to address
	resolver := r.NewAddressResolver()
	address, err := resolver.ResolveSingle(params.Account)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	// Engine layer: Get account info to check if actually rekeyed
	balanceResult, err := r.Engine.GetAccountBalanceRaw(address)
	if err != nil {
		return fmt.Errorf("failed to query account info: %w", err)
	}

	if balanceResult.AuthAddr == "" || balanceResult.AuthAddr == address {
		return fmt.Errorf("account is not rekeyed (it already signs for itself)")
	}

	// REPL layer: Show current rekey status
	fmt.Printf("Account is currently rekeyed to: %s\n", r.FormatAddress(balanceResult.AuthAddr, ""))

	// Engine layer: Prepare unrekey transaction (from=address, to=address)
	engineParams := engine.RekeyParams{
		From:       address,
		To:         address, // Rekey back to self
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
	}

	prepResult, _, err := r.Engine.PrepareRekey(engineParams)
	if err != nil {
		return err
	}

	// REPL layer: Print what we're doing
	fmt.Printf("Unrekeying account %s (back to itself)...\n", r.FormatAddress(address, ""))

	// Engine layer: Sign and submit
	submitResult, err := r.Engine.SignAndSubmit(prepResult, params.Wait)
	if err != nil {
		return fmt.Errorf("unrekey transaction failed: %w", err)
	}

	// REPL layer: Print results
	if !r.Engine.Simulate {
		fmt.Printf("Unrekey transaction submitted: %s\n", submitResult.TxID)
	}

	if params.Wait && submitResult.Confirmed {
		// Refresh auth address cache after successful unrekey
		_, err = r.Engine.AuthCache.RefreshAuthAddress(r.Engine.AlgodClient, address, r.Engine.Network)
		if err != nil {
			fmt.Printf("⚠️  Warning: failed to update auth cache: %v\n", err)
		}
		fmt.Printf("Account %s is now back to normal (no rekey in effect)\n", r.FormatAddress(address, ""))
	} else if !params.Wait {
		fmt.Printf("\nWhen confirmed, %s will sign for itself again\n", r.FormatAddress(address, ""))
	}

	return nil
}
