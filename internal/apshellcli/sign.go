// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/apshellapp"
)

// runSign handles the sign command by parsing args, delegating workflow to
// apshellapp, and rendering the result.
func (r *REPLState) runSign(args []string) error {
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

	r.printf("Loading transaction(s) from %s...\n", filepath)
	result, err := r.app().SignFile(r.commandContext(), apshellapp.SignFileRequest{
		FilePath: filepath,
		Wait:     waitForConfirmation,
	})
	if err != nil {
		return err
	}
	r.printf("Loaded %d transaction(s)\n\n", result.TxCount)
	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)

	// REPL layer: Print success message
	if len(result.TxIDs) > 0 && !r.app().IsSimulateEnabled() {
		r.println("\n✓ Transaction(s) completed successfully")
	}

	return nil
}
