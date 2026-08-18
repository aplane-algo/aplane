// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// External plugin execution and transaction intent processing

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	pluginmanager "github.com/aplane-algo/aplane/internal/plugin/manager"
)

// execPlugin runs an external plugin command and returns a structured result.
// Used by MCP for structured JSON responses. Returns (nil, false) if the command
// is not a plugin command.
func execPlugin(r *REPLState, cmdName string, args []string) (*PluginResult, bool) {
	pluginArgs, lsigArgs, err := extractPluginLsigArgs(args)
	if err != nil {
		return &PluginResult{Plugin: appresult.Plugin{Plugin: cmdName, Success: false, Message: err.Error()}}, true
	}

	execution, err := r.app().ExecutePluginCommand(r.commandContext(), cmdName, pluginArgs)
	if err != nil {
		if errors.Is(err, pluginmanager.ErrNoPluginForCommand) {
			return nil, false
		}
		return &PluginResult{Plugin: appresult.Plugin{Plugin: cmdName, Success: false, Message: err.Error()}}, true
	}

	// Process result chain (may include continuations)
	pr := &PluginResult{Plugin: appresult.Plugin{Plugin: execution.Plugin.Manifest.Name}}

	if err := processPluginResultStructured(r, pr, execution.Result, lsigArgs, execution.Plugin); err != nil {
		pr.Success = false
		pr.Message = err.Error()
	}

	return pr, true
}

// processPluginResultStructured processes a plugin result chain, collecting structured output.
// Top-level Success, Message, and Data are always updated from the latest result in the chain,
// so the final MCP response reflects the last step's state.
func processPluginResultStructured(r *REPLState, pr *PluginResult, result *jsonrpc.ExecuteResult, lsigArgs map[string][]byte, plugin *discovery.Plugin) error {
	for {
		// Update top-level fields from the current result
		pr.Success = result.Success
		pr.Message = result.Message
		pr.Data = result.Data
		pr.Presentation = result.Presentation

		if len(result.Transactions) > 0 {
			cancelled, err := reviewPluginTransactions(r, result)
			if err != nil {
				return err
			}
			if cancelled {
				return fmt.Errorf("transaction cancelled by user")
			}

			submit, err := submitPluginTransactions(r, plugin.Manifest.Name, result, lsigArgs)
			if err != nil {
				if submit != nil {
					pr.humanSteps = append(pr.humanSteps, pluginHumanStep{Output: submit.Output, Warnings: submit.Warnings})
				}
				return err
			}
			pr.humanSteps = append(pr.humanSteps, pluginHumanStep{Output: submit.Output, Warnings: submit.Warnings})
			pr.Steps = append(pr.Steps, appresult.PluginStep{Message: result.Message, TxIDs: submit.TxIDs})
		}

		if result.Continuation == nil {
			// Flatten single-step results: promote TxIDs to top level
			if len(pr.Steps) == 1 {
				pr.TxIDs = pr.Steps[0].TxIDs
				pr.Steps = nil
			}
			return nil
		}

		contResult, err := r.app().ContinuePluginCommand(r.commandContext(), plugin, result.Continuation)
		if err != nil {
			return fmt.Errorf("continuation failed: %w", err)
		}

		result = contResult
		lsigArgs = nil
	}
}

// submitPluginTransactions processes and submits plugin transactions without UI output.
func submitPluginTransactions(r *REPLState, pluginName string, result *jsonrpc.ExecuteResult, lsigArgs map[string][]byte) (*apshellapp.GroupSubmitSummary, error) {
	return r.app().SubmitPluginTransactions(r.commandContext(), pluginName, result, lsigArgs)
}

func reviewPluginTransactions(r *REPLState, result *jsonrpc.ExecuteResult) (bool, error) {
	switch result.GroupMode {
	case jsonrpc.GroupModePregroupedSigned:
		return reviewPregroupedSigned(r, result)
	case jsonrpc.GroupModePresignPlan:
		return reviewPresignPlan(r, result)
	}

	r.printf("\nPlugin generated %d transaction(s):\n", len(result.Transactions))
	for i, txn := range result.Transactions {
		r.printf("  [%d] %s transaction\n", i+1, txn.Type)
	}

	if !result.RequiresApproval || r.AutoConfirm {
		return false, nil
	}

	r.println()
	response, err := r.readApprovalResponse()
	if err != nil {
		return false, err
	}
	if response != "y" && response != "yes" {
		r.println("Transaction cancelled by user")
		return true, nil
	}
	return false, nil
}

// reviewPregroupedSigned is the mandatory client-side review for a fully
// plugin-signed, pre-grouped group. This path bypasses apsigner entirely, so this
// local review is the ONLY human-acceptance step: plugin-provided RequiresApproval
// is ignored, and non-interactive surfaces (AutoConfirm) fail closed rather than
// broadcast a group the user never saw — mirroring apsigner refusing to sign with
// no operator present.
func reviewPregroupedSigned(r *REPLState, result *jsonrpc.ExecuteResult) (bool, error) {
	encoded := make([]string, len(result.Transactions))
	for i, txn := range result.Transactions {
		encoded[i] = txn.Encoded
	}
	group, err := engine.DecodePregroupedSigned(encoded)
	if err != nil {
		return false, fmt.Errorf("pregrouped-signed: %w", err)
	}

	renderPregroupedSignedGroup(r, group.Transactions())

	if r.AutoConfirm {
		return false, fmt.Errorf("pregrouped-signed groups require interactive review and cannot be submitted in non-interactive (auto-confirm) mode")
	}

	r.println()
	response, err := r.readApprovalResponse()
	if err != nil {
		return false, err
	}
	if response != "y" && response != "yes" {
		r.println("Transaction cancelled by user")
		return true, nil
	}
	return false, nil
}

// reviewPresignPlan renders the honest presign-plan draft (managed vs plugin-signed
// slots, fee attribution) and prompts. APlane canonicalizes this group and apsigner's
// /sign approval is the authoritative gate for the managed slots, so this client
// review is a confirm on top: it prompts interactively and otherwise proceeds.
func reviewPresignPlan(r *REPLState, result *jsonrpc.ExecuteResult) (bool, error) {
	slots, err := decodePresignReviewSlots(result.Transactions, result.PluginSigners)
	if err != nil {
		return false, fmt.Errorf("presign-plan: %w", err)
	}
	renderPluginGroupReview(r, "REVIEW — plugin group; apsigner signs the APlane-managed slots", slots)

	if r.AutoConfirm {
		return false, nil
	}
	r.println()
	response, err := r.readApprovalResponse()
	if err != nil {
		return false, err
	}
	if response != "y" && response != "yes" {
		r.println("Transaction cancelled by user")
		return true, nil
	}
	return false, nil
}
