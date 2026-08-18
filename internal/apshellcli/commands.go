// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Core command definitions and transaction handlers

import (
	"fmt"
	"io"

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
func (r *REPLState) cmdValidate(args []string, _ interface{}) (command.Result, error) {
	return r.runValidate(args)
}

// cmdRekey handles the rekey command, changing an account's auth address.
func (r *REPLState) cmdRekey(args []string, _ interface{}) (command.Result, error) {
	return r.runRekey(args)
}

// cmdUnrekey handles the unrekey command, resetting an account's auth address to itself.
func (r *REPLState) cmdUnrekey(args []string, _ interface{}) (command.Result, error) {
	return r.runUnrekey(args)
}

// cmdSend handles the send command for ALGO or ASA transfers.
func (r *REPLState) cmdSend(args []string, _ interface{}) (command.Result, error) {
	return r.runSend(args)
}

// cmdSweep handles the sweep command, emptying an account or asset balance.
func (r *REPLState) cmdSweep(args []string, _ interface{}) (command.Result, error) {
	return r.runSweep(args)
}

// cmdClose handles the close command, closing an account to another address.
func (r *REPLState) cmdClose(args []string, _ interface{}) (command.Result, error) {
	return r.runClose(args)
}

// cmdSign handles the sign command, signing transactions from a file.
func (r *REPLState) cmdSign(args []string, _ interface{}) (command.Result, error) {
	return r.runSign(args)
}

// cmdOptin handles the optin command for ASAs.
func (r *REPLState) cmdOptin(args []string, _ interface{}) (command.Result, error) {
	params, err := shellrepl.ParseOptinCommand(args)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			r.renderSubmissionOutput(result.Output)
			r.renderWarnings(result.Warnings)
			r.printf("Opting into ASA %d (%s) from %s using %s...\n",
				result.Asset.AssetID, asa.DisplayRef(result.Asset), r.app().FormatAddress(result.Account, ""), result.SigningKeyType)
			if !simulated {
				r.printf("Opt-in submitted: %s\n", result.TxID)
			}
			if result.Confirmed {
				r.printf("Opt-in confirmed for %s into ASA %d (%s)\n",
					r.app().FormatAddress(result.Account, ""), result.Asset.AssetID, asa.DisplayRef(result.Asset))
			}
		})
	}, optInProjection{
		Account: result.Account, AssetID: result.Asset.AssetID, TxID: result.TxID,
		Confirmed: result.Confirmed, Simulated: simulated,
	})
}

// cmdOptout handles the optout command for ASAs.
func (r *REPLState) cmdOptout(args []string, _ interface{}) (command.Result, error) {
	params, err := shellrepl.ParseOptoutCommand(args)
	if err != nil {
		return nil, err
	}
	result, err := r.app().OptOut(r.commandContext(), optOutRequestFromParams(params))
	if err != nil {
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
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
			if !simulated {
				r.printf("Opt-out submitted: %s\n", result.TxID)
			}
			if result.Confirmed {
				r.printf("Opt-out confirmed: %s is no longer opted into ASA %d (%s)\n",
					r.app().FormatAddress(result.Account, ""), result.Asset.AssetID, asa.DisplayRef(result.Asset))
			}
		})
	}, optOutProjection{
		Account: result.Account, AssetID: result.Asset.AssetID, CloseTo: result.CloseTo,
		TxID: result.TxID, Confirmed: result.Confirmed, Simulated: simulated,
	})
}

// cmdKeyreg handles the keyreg command for online/offline key registration.
func (r *REPLState) cmdKeyreg(args []string, _ interface{}) (command.Result, error) {
	// Paste mode (no args) has interactive prompts
	if len(args) == 0 {
		return newTerminalCommandResult(nil), r.keyRegPasteMode()
	}

	cmdParams, err := shellrepl.ParseTakeCommand(args)
	if err != nil {
		return nil, err
	}

	mode := cmdParams.Mode
	incentiveEligible := cmdParams.IncentiveEligible

	if mode == "online" {
		address, err := r.app().ResolveAddress(cmdParams.From)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %w", err)
		}
		incentiveEligible, err = checkIncentiveEligibility(r, address, incentiveEligible, false)
		if err != nil {
			return nil, err
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
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			r.renderSubmissionOutput(result.Output)
			r.renderWarnings(result.Warnings)
			statusMsg := "OFFLINE"
			if mode == "online" {
				statusMsg = "ONLINE in consensus"
			}
			r.printf("Marking %s %s using %s...\n", r.app().FormatAddress(result.Account, ""), statusMsg, result.SigningKeyType)
			if !simulated {
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
		})
	}, keyRegProjection{
		Account: result.Account, Mode: result.Mode, TxID: result.TxID,
		Confirmed: result.Confirmed, Simulated: simulated,
	})
}

// executeRegisteredCommand dispatches a built-in command without rendering its
// result. The bool reports whether the command name resolved in the registry.
func (r *REPLState) executeRegisteredCommand(cmd Command) (command.Result, bool, error) {
	// Handle empty command
	if cmd.Name == "" {
		return nil, true, nil
	}

	r.applyClientCacheUpdates()

	// Lookup command in registry
	registeredCmd, ok := r.CommandRegistry.Lookup(cmd.Name)
	if !ok {
		return nil, false, nil
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
	result, err := registeredCmd.Handler.Execute(cmd.Args, ctx)
	return result, true, err
}

// executeCommandResult dispatches a built-in or plugin command without
// rendering its result.
func (r *REPLState) executeCommandResult(cmd Command) (command.Result, error) {
	result, handled, err := r.executeRegisteredCommand(cmd)
	if handled || err != nil {
		return result, err
	}

	pluginResult, isPlugin := execPlugin(r, cmd.Name, cmd.Args)
	if !isPlugin {
		return nil, &unknownCommandError{name: cmd.Name}
	}
	result, err = newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() { renderPluginResult(r, pluginResult) })
	}, projectPluginResult(pluginResult))
	if err != nil {
		return nil, err
	}
	if !pluginResult.Success {
		message := pluginResult.Message
		if message == "" {
			message = "plugin command failed"
		}
		result.(*shellCommandResult).terminalErr = fmt.Errorf("%s", message)
	}
	return result, nil
}

type unknownCommandError struct {
	name string
}

func (e *unknownCommandError) Error() string {
	return fmt.Sprintf("unknown command: %s", e.name)
}

// executeCommand dispatches a command and renders its human presentation.
func (r *REPLState) executeCommand(cmd Command) error {
	result, err := r.executeCommandResult(cmd)
	if err != nil {
		if unknown, ok := err.(*unknownCommandError); ok {
			r.printf("Unknown command: %s\nType 'help' for available commands\n", unknown.name)
			return nil
		}
		if result != nil {
			if renderErr := result.RenderText(r.Out); renderErr != nil {
				r.renderErrorSubmissionOutput(renderErr)
				return renderErr
			}
		}
		r.renderErrorSubmissionOutput(err)
		return err
	}
	if terminal, ok := result.(interface{ terminalFailure() error }); ok {
		if err := terminal.terminalFailure(); err != nil {
			r.renderErrorSubmissionOutput(err)
			return err
		}
	}
	if result != nil {
		if err := result.RenderText(r.Out); err != nil {
			r.renderErrorSubmissionOutput(err)
			return err
		}
	}
	return nil
}
