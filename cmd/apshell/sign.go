// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/algo"
)

// signWithEngine signs and submits transaction(s) from a file using Engine pattern.
// REPL layer: file path handling, UI output
// Engine layer: signing and submission
func (r *REPLState) signWithEngine(args []string) error {
	// REPL layer: Parse arguments
	if len(args) < 1 {
		return fmt.Errorf("usage: sign <file> [nowait]")
	}

	filepath := args[0]
	waitForConfirmation := true

	// Check for nowait flag
	for _, arg := range args[1:] {
		if arg == "nowait" {
			waitForConfirmation = false
		}
	}

	// REPL layer: Load and parse transactions from file
	fmt.Printf("Loading transaction(s) from %s...\n", filepath)
	txns, err := algo.ParseTransactionFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to parse transaction file: %w", err)
	}

	fmt.Printf("Loaded %d transaction(s)\n\n", len(txns))

	// Engine layer: Sign and submit transactions
	result, err := r.Engine.SignAndSubmitTransactionsFromFile(txns, waitForConfirmation)
	if err != nil {
		return err
	}

	// REPL layer: Print success message
	if len(result.TxIDs) > 0 && !r.Engine.Simulate {
		fmt.Println("\n✓ Transaction(s) completed successfully")
	}

	return nil
}
