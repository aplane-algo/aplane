// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Rekey command implementations for account rekeying operations.

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

// listRekeys lists all rekeyed accounts from cache.
func listRekeys(r *REPLState) error {
	r.println("Listing rekeyed accounts (from cache)...")
	r.println()

	result, err := r.app().ListRekeys(r.commandContext())
	if err != nil {
		return err
	}
	if len(result.Rekeys) == 0 {
		r.println("No rekeyed accounts found.")
		return nil
	}

	for _, rk := range result.Rekeys {
		r.printf("%s\nauth: %s\n\n",
			r.app().FormatAddress(rk.Address, rk.AuthAddress),
			r.app().FormatAddress(rk.AuthAddress, ""))
	}

	return nil
}

// runRekey handles the rekey command by parsing args, delegating workflow to
// apshellapp, and rendering the result.
func (r *REPLState) runRekey(args []string) error {
	// Handle special subcommands (list, refresh) - these stay in REPL layer
	if len(args) == 0 {
		return printRekeyUsage(r)
	}
	if args[0] == "list" {
		if len(args) != 1 {
			return fmt.Errorf("usage: rekey list")
		}
		return listRekeys(r)
	}
	if args[0] == "refresh" {
		switch len(args) {
		case 1:
			return refreshAuthCache(r)
		case 2:
			return refreshAuthAddress(r, args[1])
		default:
			return fmt.Errorf("usage: rekey refresh [<address|alias>]")
		}
	}

	params, err := shellrepl.ParseRekeyCommand(args, false)
	if err != nil {
		return err
	}

	result, err := r.app().Rekey(r.commandContext(), apshellapp.RekeyRequest{
		Account:    params.Account,
		Target:     params.Signer,
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
		LsigArgs:   params.LsigArgs,
		Wait:       params.Wait,
	})
	if err != nil {
		return err
	}

	for _, line := range renderRekeyLines(result.PreSubmitLines, result, r) {
		r.println(line)
	}

	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)
	if !r.app().IsSimulateEnabled() {
		r.printf("Rekey transaction submitted: %s\n", result.TxID)
	}

	if result.Confirmed {
		if result.RefreshWarning != "" {
			r.printf("⚠️  Warning: failed to update auth cache: %v\n", result.RefreshWarning)
		}
		for _, line := range renderRekeyLines(result.ConfirmedLines, result, r) {
			r.println(line)
		}
	} else if !params.Wait {
		for _, line := range renderRekeyLines(result.PendingLines, result, r) {
			r.println(line)
		}
	}

	return nil
}

func printRekeyUsage(r *REPLState) error {
	for _, line := range rekeyUsageLines() {
		r.printf("  %s\n", line)
	}
	return nil
}

func rekeyUsageLines() []string {
	return []string{
		"rekey list",
		"rekey refresh",
		"rekey refresh <address|alias>",
		"rekey <account> to <signer> [fee=<microalgos>] [nowait] [arg:name=value]",
	}
}

// runUnrekey handles the unrekey command by parsing args, delegating workflow
// to apshellapp, and rendering the result.
func (r *REPLState) runUnrekey(args []string) error {
	params, err := shellrepl.ParseRekeyCommand(args, true) // true = isUnrekey
	if err != nil {
		return err
	}

	result, err := r.app().Unrekey(r.commandContext(), apshellapp.UnrekeyRequest{
		Account:    params.Account,
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
		LsigArgs:   params.LsigArgs,
		Wait:       params.Wait,
	})
	if err != nil {
		return err
	}

	for _, line := range renderRekeyLines(result.PreSubmitLines, result, r) {
		r.println(line)
	}
	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)
	if !r.app().IsSimulateEnabled() {
		r.printf("Unrekey transaction submitted: %s\n", result.TxID)
	}
	if result.Confirmed {
		if result.RefreshWarning != "" {
			r.printf("⚠️  Warning: failed to update auth cache: %v\n", result.RefreshWarning)
		}
		for _, line := range renderRekeyLines(result.ConfirmedLines, result, r) {
			r.println(line)
		}
	} else if !params.Wait {
		for _, line := range renderRekeyLines(result.PendingLines, result, r) {
			r.println(line)
		}
	}

	return nil
}

func renderRekeyLines(lines []string, result *apshellapp.RekeyCommandResult, r *REPLState) []string {
	rendered := make([]string, 0, len(lines))
	for _, line := range lines {
		rendered = append(rendered, formatRekeyResultLine(line, result, r))
	}
	return rendered
}

func formatRekeyResultLine(line string, result *apshellapp.RekeyCommandResult, r *REPLState) string {
	line = strings.ReplaceAll(line, "{from}", r.app().FormatAddress(result.From, ""))
	line = strings.ReplaceAll(line, "{to}", r.app().FormatAddress(result.To, ""))
	line = strings.ReplaceAll(line, "{current_auth}", r.app().FormatAddress(result.CurrentAuthAddress, ""))
	return line
}
