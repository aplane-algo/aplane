// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Sweep command implementation for consolidating ALGO or ASA balances.

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

// runSweep handles the sweep command by parsing args, delegating workflow to
// apshellapp, and rendering the result.
func (r *REPLState) runSweep(args []string) error {
	params, err := shellrepl.ParseSweepCommand(args)
	if err != nil {
		return err
	}

	result, err := r.app().Sweep(r.commandContext(), apshellapp.SweepRequest{
		AssetRef:    params.Asset.String(),
		FromRaw:     params.FromRaw,
		ToRaw:       params.ToRaw,
		LeavingText: params.Leaving.String(),
		Fee:         params.Fee,
		UseFlatFee:  params.UseFlatFee,
		LsigArgs:    params.LsigArgs,
		Wait:        params.Wait,
	})
	if err != nil && result == nil {
		return err
	}

	for _, line := range renderSweepLines(result.InfoLines, result, r) {
		r.println(line)
	}

	r.println()
	r.print(renderSweepLine(result.HeaderLine, result, r))
	r.println("\n" + strings.Repeat("=", 60))

	for i, item := range result.Items {
		r.printf("\n[%d/%d] Processing %s...\n", i+1, len(result.Items), r.app().FormatAddress(item.From, ""))
		if item.SkippedReason != "" {
			r.printf("  - Skipping (%s)\n", item.SkippedReason)
			continue
		}
		r.renderSubmissionOutput(item.Output)
		r.renderWarnings(item.Warnings)
		if item.Error != "" {
			r.printf("  ✗ %s\n", item.Error)
			continue
		}
		r.printf("  Sending %s...\n", asa.DisplayString(item.Amount))
		if !r.app().IsSimulateEnabled() {
			r.printf("  ✓ Transaction submitted: %s\n", item.TxID)
		}
		if item.Confirmed {
			r.printf("  ✓ Confirmed\n")
		}
	}

	r.println("\n" + strings.Repeat("=", 60))
	for _, line := range renderSweepLines(result.SummaryLines, result, r) {
		r.println(line)
	}
	return err
}

func renderSweepLines(lines []string, result *apshellapp.SweepCommandResult, r *REPLState) []string {
	rendered := make([]string, 0, len(lines))
	for _, line := range lines {
		rendered = append(rendered, renderSweepLine(line, result, r))
	}
	return rendered
}

func renderSweepLine(line string, result *apshellapp.SweepCommandResult, r *REPLState) string {
	aliasedFrom := make([]string, 0, len(result.FromAddresses))
	for _, addr := range result.FromAddresses {
		aliasedFrom = append(aliasedFrom, r.app().FormatAddress(addr, ""))
	}
	line = strings.ReplaceAll(line, "{from_addresses}", strings.Join(aliasedFrom, ", "))
	line = strings.ReplaceAll(line, "{to}", r.app().FormatAddress(result.ToAddress, ""))
	return line
}
