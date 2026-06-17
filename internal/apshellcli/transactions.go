// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Transaction-related commands:
// - validate: Validate signing capability via 0 ALGO self-send
// - close: Close an account by sending all ALGO to destination
//
// See also:
// - send.go: Send/transfer commands (single, set, atomic)
// - sweep.go: Sweep command for balance consolidation
// - rekey.go: Rekey/unrekey commands

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

// runValidate handles the validate command by parsing args, delegating
// workflow to apshellapp, and rendering the result.
func (r *REPLState) runValidate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: validate <account> [arg:name=value]\n  Sends a 0 ALGO self-send transaction to validate account signing capability")
	}

	var lsigArgs map[string][]byte
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "arg:") {
			return fmt.Errorf("unknown validate argument: %s", arg)
		}
		name, value, err := cmdspec.ParseLsigArg(arg)
		if err != nil {
			return err
		}
		if lsigArgs == nil {
			lsigArgs = make(map[string][]byte)
		}
		lsigArgs[name] = value
	}

	result, err := r.app().Validate(r.commandContext(), apshellapp.ValidateRequest{
		Account:  args[0],
		LsigArgs: lsigArgs,
	})
	result, err = checkedValidateResult(result, err)
	if err != nil {
		return err
	}
	for idx, item := range result.Items {
		if len(result.Items) > 1 {
			r.printf("[%d/%d] Validating %s\n", idx+1, len(result.Items), r.app().FormatAddress(item.Address, ""))
		}
		r.renderSubmissionOutput(item.Output)
		r.renderWarnings(item.Warnings)
		if item.Error != "" {
			r.printf("  ✗ Failed: %s\n", item.Error)
		}
		if item.Error == "" && !r.app().IsSimulateEnabled() {
			r.printf("  ✓ Validated successfully (txid: %s)\n", item.TxID)
		}
		if len(result.Items) > 1 {
			r.println()
		}
	}

	for _, line := range result.SummaryLines {
		r.println(line)
	}
	if err != nil {
		return nil
	}
	return nil
}

func checkedValidateResult(result *apshellapp.ValidateCommandResult, err error) (*apshellapp.ValidateCommandResult, error) {
	if result != nil {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("validate returned no result")
}

// runClose handles the close command by parsing args, delegating workflow to
// apshellapp, and rendering the result.
func (r *REPLState) runClose(args []string) error {
	// Parse command using dedicated parser
	params, err := shellrepl.ParseCloseCommand(args)
	if err != nil {
		return err
	}

	result, err := r.app().Close(r.commandContext(), closeRequestFromParams(params))
	if err != nil {
		return err
	}

	for _, line := range renderCloseLines(result.PreSubmitLines, result, r) {
		r.println(line)
	}
	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)
	if !r.app().IsSimulateEnabled() {
		r.printf("Close transaction submitted: %s\n", result.TxID)
	}
	if result.Confirmed {
		for _, line := range renderCloseLines(result.ConfirmedLines, result, r) {
			r.println(line)
		}
	}

	return nil
}

func renderCloseLines(lines []string, result *apshellapp.CloseCommandResult, r *REPLState) []string {
	rendered := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.ReplaceAll(line, "{from}", r.app().FormatAddress(result.From, ""))
		line = strings.ReplaceAll(line, "{to}", r.app().FormatAddress(result.CloseTo, ""))
		rendered = append(rendered, line)
	}
	return rendered
}
