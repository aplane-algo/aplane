// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Core command definitions and transaction handlers

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

// Command represents a parsed command from the REPL
type Command struct {
	Name    string
	Args    []string
	RawArgs string // Raw argument string (preserves quotes for raw-tail commands like js/jssave)
}

// Transaction command wrappers

// cmdValidate handles the validate command, checking account status.
func (r *REPLState) cmdValidate(args []string, _ interface{}) error {
	return r.runValidate(args)
}

// cmdRekey handles the rekey command, changing an account's auth address.
func (r *REPLState) cmdRekey(args []string, _ interface{}) error {
	return r.runRekey(args)
}

// cmdUnrekey handles the unrekey command, resetting an account's auth address to itself.
func (r *REPLState) cmdUnrekey(args []string, _ interface{}) error {
	return r.runUnrekey(args)
}

// cmdSend handles the send command for ALGO or ASA transfers.
func (r *REPLState) cmdSend(args []string, _ interface{}) error {
	return r.runSend(args)
}

// cmdSweep handles the sweep command, emptying an account or asset balance.
func (r *REPLState) cmdSweep(args []string, _ interface{}) error {
	return r.runSweep(args)
}

// cmdClose handles the close command, closing an account to another address.
func (r *REPLState) cmdClose(args []string, _ interface{}) error {
	return r.runClose(args)
}

// cmdSign handles the sign command, signing transactions from a file.
func (r *REPLState) cmdSign(args []string, _ interface{}) error {
	return r.runSign(args)
}

// cmdOptin handles the optin command for ASAs.
func (r *REPLState) cmdOptin(args []string, _ interface{}) error {
	params, err := shellrepl.ParseOptinCommand(args)
	if err != nil {
		return err
	}
	result, err := r.app().OptIn(r.commandContext(), apshellapp.OptInRequest{
		Account:    params.From,
		AssetRef:   params.ASARef.String(),
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
		LsigArgs:   params.LsigArgs,
		Wait:       params.Wait,
	})
	if err != nil {
		return err
	}

	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)
	r.printf("Opting into ASA %d (%s) from %s using %s...\n",
		result.Asset.AssetID, asa.DisplayRef(result.Asset), r.app().FormatAddress(result.Account, ""), result.SigningKeyType)
	if !r.app().IsSimulateEnabled() {
		r.printf("Opt-in submitted: %s\n", result.TxID)
	}
	if result.Confirmed {
		r.printf("Opt-in confirmed for %s into ASA %d (%s)\n",
			r.app().FormatAddress(result.Account, ""), result.Asset.AssetID, asa.DisplayRef(result.Asset))
	}

	return nil
}

// cmdOptout handles the optout command for ASAs.
func (r *REPLState) cmdOptout(args []string, _ interface{}) error {
	params, err := shellrepl.ParseOptoutCommand(args)
	if err != nil {
		return err
	}
	result, err := r.app().OptOut(r.commandContext(), optOutRequestFromParams(params))
	if err != nil {
		return err
	}

	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)
	if result.AssetBalance > 0 {
		r.printf("Opting out of ASA %d (%s) from %s, sending %d units to %s using %s...\n",
			result.Asset.AssetID, asa.DisplayRef(result.Asset), r.app().FormatAddress(result.Account, ""),
			result.AssetBalance, r.app().FormatAddress(result.CloseTo, ""), result.SigningKeyType)
	} else {
		r.printf("Opting out of ASA %d (%s) from %s using %s...\n",
			result.Asset.AssetID, asa.DisplayRef(result.Asset), r.app().FormatAddress(result.Account, ""), result.SigningKeyType)
	}
	if !r.app().IsSimulateEnabled() {
		r.printf("Opt-out submitted: %s\n", result.TxID)
	}
	if result.Confirmed {
		r.printf("Opt-out confirmed: %s is no longer opted into ASA %d (%s)\n",
			r.app().FormatAddress(result.Account, ""), result.Asset.AssetID, asa.DisplayRef(result.Asset))
	}

	return nil
}

// cmdKeyreg handles the keyreg command for online/offline key registration.
func (r *REPLState) cmdKeyreg(args []string, _ interface{}) error {
	// Paste mode (no args) has interactive prompts
	if len(args) == 0 {
		return r.keyRegPasteMode()
	}

	cmdParams, err := shellrepl.ParseTakeCommand(args)
	if err != nil {
		return err
	}

	mode := cmdParams.Mode
	incentiveEligible := cmdParams.IncentiveEligible

	if mode == "online" {
		address, err := r.app().ResolveAddress(cmdParams.From)
		if err != nil {
			return fmt.Errorf("failed to resolve address: %w", err)
		}
		incentiveEligible, err = checkIncentiveEligibility(r, address, incentiveEligible, false)
		if err != nil {
			return err
		}
	}

	result, err := r.app().KeyReg(r.commandContext(), apshellapp.KeyRegRequest{
		Account:           cmdParams.From,
		Mode:              mode,
		VoteKey:           cmdParams.VoteKey,
		SelectionKey:      cmdParams.SelKey,
		StateProofKey:     cmdParams.SProofKey,
		VoteFirst:         cmdParams.VoteFirst,
		VoteLast:          cmdParams.VoteLast,
		KeyDilution:       cmdParams.KeyDilution,
		IncentiveEligible: incentiveEligible,
		LsigArgs:          cmdParams.LsigArgs,
		Wait:              cmdParams.Wait,
	})
	if err != nil {
		return err
	}

	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)
	var statusMsg string
	switch mode {
	case "online":
		statusMsg = "ONLINE in consensus"
	case "offline":
		statusMsg = "OFFLINE"
	}
	r.printf("Marking %s %s using %s...\n", r.app().FormatAddress(result.Account, ""), statusMsg, result.SigningKeyType)
	if !r.app().IsSimulateEnabled() {
		r.printf("Key registration submitted: %s\n", result.TxID)
	}
	if result.Confirmed {
		switch mode {
		case "online":
			r.printf("\n%s is now ONLINE (participating in consensus)\n", r.app().FormatAddress(result.Account, ""))
			r.printf("Participation valid from round %d to %d\n", result.VoteFirst, result.VoteLast)
		case "offline":
			r.printf("\n%s is now OFFLINE\n", r.app().FormatAddress(result.Account, ""))
		}
	} else {
		switch mode {
		case "online":
			r.printf("\nWhen confirmed, %s will be marked ONLINE\n", r.app().FormatAddress(result.Account, ""))
		case "offline":
			r.printf("\nWhen confirmed, %s will be marked OFFLINE (temporary)\n", r.app().FormatAddress(result.Account, ""))
		}
	}

	return nil
}

// executeCommand dispatches a command to its handler via the registry
func (r *REPLState) executeCommand(cmd Command) error {
	// Handle empty command
	if cmd.Name == "" {
		return nil
	}

	r.applyClientCacheUpdates()

	// Lookup command in registry
	registeredCmd, ok := r.CommandRegistry.Lookup(cmd.Name)
	if !ok {
		// Try external plugins
		err := executeExternalPlugin(r, cmd)
		if err != nil {
			r.renderErrorSubmissionOutput(err)
		}
		return err
	}

	// Build context for command execution
	internal := &command.InternalContext{
		REPLState: r, // Provide full REPLState access for internal commands
	}
	internal.SetOut(r.Out)

	state := r.app().ExecutionState()
	ctx := &command.Context{
		Network:     state.Network,
		IsConnected: state.IsConnected,
		WriteMode:   state.WriteMode,
		Simulate:    state.Simulate,
		RawArgs:     cmd.RawArgs,
		Internal:    internal,
	}

	// Execute command via registry
	err := registeredCmd.Handler.Execute(cmd.Args, ctx)
	if err != nil {
		r.renderErrorSubmissionOutput(err)
	}
	return err
}
