// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Transaction execution helpers to reduce boilerplate in command handlers.

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/engine"
)

// printAtomicGroupResult prints the standard success message for atomic groups.
func (r *REPLState) printAtomicGroupResult(result *engine.AtomicSubmitResult) {
	if !r.Engine.Simulate {
		fmt.Printf("✓ Atomic transaction group submitted successfully\n")
		fmt.Printf("Group contains %d transaction(s)\n", len(result.TxIDs))
		if len(result.TxIDs) > 0 {
			fmt.Printf("First transaction ID: %s\n", result.TxIDs[0])
		}
	}
}

// executeTransaction handles the common pattern of SignAndSubmit + basic output.
// This consolidates the repeated boilerplate across transaction commands.
//
// Parameters:
//   - prep: The prepared transaction from Engine.Prepare* methods
//   - wait: Whether to wait for confirmation
//   - operationName: Name for error/output messages (e.g., "opt-in", "rekey transaction")
//
// Returns the result for the caller to handle any confirmation-specific messages.
func (r *REPLState) executeTransaction(
	prep *engine.TransactionPrepResult,
	wait bool,
	operationName string,
) (*engine.SubmitResult, error) {
	result, err := r.Engine.SignAndSubmit(prep, wait)
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", operationName, err)
	}

	// Capitalize first letter for display
	displayName := operationName
	if len(operationName) > 0 {
		displayName = strings.ToUpper(operationName[:1]) + operationName[1:]
	}
	if !r.Engine.Simulate {
		fmt.Printf("%s submitted: %s\n", displayName, result.TxID)
	}

	return result, nil
}
