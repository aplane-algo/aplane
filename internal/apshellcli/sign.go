// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
)

// runSign handles the sign command by parsing args, delegating workflow to
// apshellapp, and rendering the result.
func (r *REPLState) runSign(args []string) (command.Result, error) {
	// REPL layer: Parse arguments
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: sign <file> [nowait]")
	}

	filepath := args[0]
	waitForConfirmation := true

	// Check for nowait flag
	for _, arg := range args[1:] {
		if arg == "nowait" {
			waitForConfirmation = false
		}
	}

	result, err := r.app().SignFile(r.commandContext(), apshellapp.SignFileRequest{
		FilePath: filepath,
		Wait:     waitForConfirmation,
	})
	if err != nil {
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			r.printf("Loading transaction(s) from %s...\n", filepath)
			r.printf("Loaded %d transaction(s)\n\n", result.TxCount)
			r.renderSubmissionOutput(result.Output)
			r.renderWarnings(result.Warnings)
			if len(result.TxIDs) > 0 && !simulated {
				r.println("\n✓ Transaction(s) completed successfully")
			}
		})
	}, signFileProjection{
		TransactionCount: result.TxCount, TxIDs: result.TxIDs,
		Confirmed: result.Confirmed, Simulated: simulated,
	})
}
