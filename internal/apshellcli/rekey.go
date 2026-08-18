// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Rekey command implementations for account rekeying operations.

import (
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

// runRekey handles the rekey command by parsing args, delegating workflow to
// apshellapp, and rendering the result.
func (r *REPLState) runRekey(args []string) (command.Result, error) {
	// Handle special subcommands (list, refresh) - these stay in REPL layer
	if len(args) == 0 {
		return newShellCommandResult(func(w io.Writer) error {
			for _, line := range rekeyUsageLines() {
				if _, err := fmt.Fprintf(w, "  %s\n", line); err != nil {
					return err
				}
			}
			return nil
		}, rekeyProjection{Mode: "usage"})
	}
	if args[0] == "list" {
		if len(args) != 1 {
			return nil, fmt.Errorf("usage: rekey list")
		}
		result, err := r.app().ListRekeys(r.commandContext())
		if err != nil {
			return nil, err
		}
		projection := rekeyProjection{Mode: "list", Entries: make([]rekeyEntryProjection, len(result.Rekeys))}
		for i, item := range result.Rekeys {
			projection.Entries[i] = rekeyEntryProjection{Address: item.Address, AuthAddress: item.AuthAddress}
		}
		return newShellCommandResult(func(w io.Writer) error {
			return r.withOutput(w, func() {
				r.println("Listing rekeyed accounts (from cache)...")
				r.println()
				if len(result.Rekeys) == 0 {
					r.println("No rekeyed accounts found.")
					return
				}
				for _, item := range result.Rekeys {
					r.printf("%s\nauth: %s\n\n",
						r.app().FormatAddress(item.Address, item.AuthAddress),
						r.app().FormatAddress(item.AuthAddress, ""))
				}
			})
		}, projection)
	}
	if args[0] == "refresh" {
		switch len(args) {
		case 1:
			if err := r.app().RefreshAuthCache(r.commandContext()); err != nil {
				return nil, err
			}
			return newShellCommandResult(func(w io.Writer) error {
				_, err := fmt.Fprintln(w, "✓ Auth cache refreshed")
				return err
			}, rekeyProjection{Mode: "refresh_all"})
		case 2:
			result, err := r.app().RefreshAuthAddress(r.commandContext(), args[1])
			if err != nil {
				return nil, err
			}
			projection := rekeyProjection{Mode: "refresh", Refreshed: []authRefreshProjection{{
				Address: result.Address, AuthAddress: result.AuthAddress, IsRekeyed: result.IsRekeyed,
			}}}
			return newShellCommandResult(func(w io.Writer) error {
				return r.withOutput(w, func() {
					r.printf("✓ Auth cache refreshed for %s\n", r.app().FormatAddress(result.Address, ""))
					if result.IsRekeyed {
						r.printf("auth: %s\n", r.app().FormatAddress(result.AuthAddress, ""))
					} else {
						r.println("auth: self")
					}
				})
			}, projection)
		default:
			return nil, fmt.Errorf("usage: rekey refresh [<address|alias>]")
		}
	}

	params, err := shellrepl.ParseRekeyCommand(args, false)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	return rekeyTransactionResult(r, result, params.Wait, simulated, "Rekey transaction submitted")
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
func (r *REPLState) runUnrekey(args []string) (command.Result, error) {
	params, err := shellrepl.ParseRekeyCommand(args, true) // true = isUnrekey
	if err != nil {
		return nil, err
	}

	result, err := r.app().Unrekey(r.commandContext(), apshellapp.UnrekeyRequest{
		Account:    params.Account,
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
		LsigArgs:   params.LsigArgs,
		Wait:       params.Wait,
	})
	if err != nil {
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	return rekeyTransactionResult(r, result, params.Wait, simulated, "Unrekey transaction submitted")
}

func rekeyTransactionResult(r *REPLState, result *apshellapp.RekeyCommandResult, wait, simulated bool, submittedLabel string) (command.Result, error) {
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			for _, line := range renderRekeyLines(result.PreSubmitLines, result, r) {
				r.println(line)
			}
			r.renderSubmissionOutput(result.Output)
			r.renderWarnings(result.Warnings)
			if !simulated {
				r.printf("%s: %s\n", submittedLabel, result.TxID)
			}
			if result.Confirmed {
				if result.RefreshWarning != "" {
					r.printf("⚠️  Warning: failed to update auth cache: %v\n", result.RefreshWarning)
				}
				for _, line := range renderRekeyLines(result.ConfirmedLines, result, r) {
					r.println(line)
				}
			} else if !wait {
				for _, line := range renderRekeyLines(result.PendingLines, result, r) {
					r.println(line)
				}
			}
		})
	}, rekeyProjection{
		Mode: "transaction", From: result.From, To: result.To, TxID: result.TxID,
		Confirmed: result.Confirmed, Simulated: simulated,
	})
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
