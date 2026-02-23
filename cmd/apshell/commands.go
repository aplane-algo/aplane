// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Core command definitions and transaction handlers

import (
	"fmt"

	"github.com/aplane-algo/aplane/cmd/apshell/internal/repl"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/engine"
)

// Command represents a parsed command from the REPL
type Command struct {
	Name    string
	Args    []string
	RawArgs string // Raw argument string (preserves quotes, used by js command)
}

// Transaction command wrappers

// cmdValidate handles the validate command, checking account status.
func (r *REPLState) cmdValidate(args []string, _ interface{}) error {
	return r.validateWithEngine(args)
}

// cmdRekey handles the rekey command, changing an account's auth address.
func (r *REPLState) cmdRekey(args []string, _ interface{}) error {
	return r.rekeyWithEngine(args)
}

// cmdUnrekey handles the unrekey command, resetting an account's auth address to itself.
func (r *REPLState) cmdUnrekey(args []string, _ interface{}) error {
	return r.unrekeyWithEngine(args)
}

// cmdSend handles the send command for ALGO or ASA transfers.
func (r *REPLState) cmdSend(args []string, _ interface{}) error {
	return r.sendWithEngine(args)
}

// cmdSweep handles the sweep command, emptying an account or asset balance.
func (r *REPLState) cmdSweep(args []string, _ interface{}) error {
	return r.sweepWithEngine(args)
}

// cmdClose handles the close command, closing an account to another address.
func (r *REPLState) cmdClose(args []string, _ interface{}) error {
	return r.closeWithEngine(args)
}

// cmdSign handles the sign command, signing transactions from a file.
func (r *REPLState) cmdSign(args []string, _ interface{}) error {
	return r.signWithEngine(args)
}

// cmdOptin handles the optin command for ASAs.
func (r *REPLState) cmdOptin(args []string, _ interface{}) error {
	params, err := repl.ParseOptinCommand(args)
	if err != nil {
		return err
	}

	resolver := r.NewAddressResolver()
	address, err := resolver.ResolveSingle(params.From)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	asaID, err := r.Engine.AsaCache.ResolveASAReference(params.ASARef, r.Engine.Network)
	if err != nil {
		return fmt.Errorf("failed to resolve ASA '%s': %w", params.ASARef, err)
	}

	asaInfo, err := r.Engine.GetASAInfo(asaID)
	if err != nil {
		return fmt.Errorf("failed to get ASA info: %w", err)
	}

	prep, err := r.Engine.PrepareOptIn(engine.OptInParams{
		Account:    address,
		AssetID:    asaID,
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Opting into ASA %d (%s) from %s using %s...\n",
		asaID, asaInfo.UnitName, r.FormatAddress(address, ""), prep.SigningContext.DisplayKeyType())

	result, err := r.executeTransaction(prep, params.Wait, "opt-in")
	if err != nil {
		return err
	}

	if params.Wait && result.Confirmed {
		fmt.Printf("Opt-in confirmed for %s into ASA %d (%s)\n",
			r.FormatAddress(address, ""), asaID, asaInfo.UnitName)
	}

	return nil
}

// cmdOptout handles the optout command for ASAs.
func (r *REPLState) cmdOptout(args []string, _ interface{}) error {
	// Parse command using dedicated parser
	params, err := repl.ParseOptoutCommand(args)
	if err != nil {
		return err
	}

	// Resolve ASA reference
	asaID, err := r.Engine.AsaCache.ResolveASAReference(params.ASARef, r.Engine.Network)
	if err != nil {
		return fmt.Errorf("failed to resolve ASA '%s': %w", params.ASARef, err)
	}

	asaInfo, err := r.Engine.GetASAInfo(asaID)
	if err != nil {
		return fmt.Errorf("failed to get ASA info: %w", err)
	}

	// Resolve account address
	resolver := r.NewAddressResolver()
	accountAddr, err := resolver.ResolveSingle(params.Account)
	if err != nil {
		return fmt.Errorf("failed to resolve account '%s': %w", params.Account, err)
	}

	// Resolve close-to address if provided
	var closeToAddr string
	if params.CloseTo != "" {
		closeToAddr, err = resolver.ResolveSingle(params.CloseTo)
		if err != nil {
			return fmt.Errorf("failed to resolve close-to address '%s': %w", params.CloseTo, err)
		}
	}

	// Prepare opt-out via Engine
	prep, checkResult, err := r.Engine.PrepareOptOut(engine.OptOutParams{
		Account: accountAddr,
		AssetID: asaID,
		CloseTo: closeToAddr,
	})
	if err != nil {
		return err
	}

	// Display what we're doing
	if checkResult.AssetBalance > 0 {
		fmt.Printf("Opting out of ASA %d (%s) from %s, sending %d units to %s using %s...\n",
			asaID, asaInfo.UnitName, r.FormatAddress(accountAddr, ""),
			checkResult.AssetBalance, r.FormatAddress(closeToAddr, ""),
			prep.SigningContext.DisplayKeyType())
	} else {
		fmt.Printf("Opting out of ASA %d (%s) from %s using %s...\n",
			asaID, asaInfo.UnitName, r.FormatAddress(accountAddr, ""),
			prep.SigningContext.DisplayKeyType())
	}

	// Sign and submit
	result, err := r.executeTransaction(prep, params.Wait, "opt-out")
	if err != nil {
		return err
	}

	if params.Wait && result.Confirmed {
		fmt.Printf("Opt-out confirmed: %s is no longer opted into ASA %d (%s)\n",
			r.FormatAddress(accountAddr, ""), asaID, asaInfo.UnitName)
	}

	return nil
}

// cmdKeyreg handles the keyreg command for online/offline key registration.
func (r *REPLState) cmdKeyreg(args []string, _ interface{}) error {
	// Paste mode (no args) has interactive prompts
	if len(args) == 0 {
		return r.keyRegPasteMode()
	}

	cmdParams, err := repl.ParseTakeCommand(args)
	if err != nil {
		return err
	}

	resolver := r.NewAddressResolver()
	address, err := resolver.ResolveSingle(cmdParams.From)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	mode := cmdParams.Mode
	voteKey := cmdParams.VoteKey
	selKey := cmdParams.SelKey
	sProofKey := cmdParams.SProofKey
	voteFirst := cmdParams.VoteFirst
	voteLast := cmdParams.VoteLast
	keyDilution := cmdParams.KeyDilution
	incentiveEligible := cmdParams.IncentiveEligible

	if mode == "offline" {
		voteKey = ""
		selKey = ""
		sProofKey = ""
		voteFirst = 0
		voteLast = 0
		keyDilution = 0
	}

	if mode == "online" {
		incentiveEligible, err = r.checkIncentiveEligibility(address, incentiveEligible, false)
		if err != nil {
			return err
		}
	}

	prep, err := r.Engine.PrepareKeyReg(engine.KeyRegParams{
		Account:           address,
		Mode:              mode,
		VoteKey:           voteKey,
		SelectionKey:      selKey,
		StateProofKey:     sProofKey,
		VoteFirst:         voteFirst,
		VoteLast:          voteLast,
		KeyDilution:       keyDilution,
		IncentiveEligible: incentiveEligible,
	})
	if err != nil {
		return err
	}

	var statusMsg string
	switch mode {
	case "online":
		statusMsg = "ONLINE in consensus"
	case "offline":
		statusMsg = "OFFLINE"
	}
	fmt.Printf("Marking %s %s using %s...\n", r.FormatAddress(address, ""), statusMsg, prep.SigningContext.DisplayKeyType())

	result, err := r.executeTransaction(prep, cmdParams.Wait, "key registration")
	if err != nil {
		return err
	}

	if cmdParams.Wait && result.Confirmed {
		switch mode {
		case "online":
			fmt.Printf("\n%s is now ONLINE (participating in consensus)\n", r.FormatAddress(address, ""))
			fmt.Printf("Participation valid from round %d to %d\n", voteFirst, voteLast)
		case "offline":
			fmt.Printf("\n%s is now OFFLINE\n", r.FormatAddress(address, ""))
		}
	} else {
		switch mode {
		case "online":
			fmt.Printf("\nWhen confirmed, %s will be marked ONLINE\n", r.FormatAddress(address, ""))
		case "offline":
			fmt.Printf("\nWhen confirmed, %s will be marked OFFLINE (temporary)\n", r.FormatAddress(address, ""))
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

	// Lookup command in registry
	registeredCmd, ok := r.CommandRegistry.Lookup(cmd.Name)
	if !ok {
		// Try external plugins
		return r.executeExternalPlugin(cmd)
	}

	// Build context for command execution
	ctx := &command.Context{
		Network:     r.Engine.Network,
		IsConnected: r.Engine.SignerClient != nil,
		WriteMode:   r.Engine.WriteMode,
		Simulate:    r.Engine.Simulate,
		RawArgs:     cmd.RawArgs,
		Internal: &command.InternalContext{
			REPLState: r, // Provide full REPLState access for internal commands and plugins
			PluginAPI: command.NewPluginAPI(
				r.Engine.AlgodClient,
				r.Engine.Network,
				&r.Engine.AsaCache,
				&r.Engine.SignerCache,
				&r.Engine.AuthCache,
				&r.Engine.AliasCache,
				r.Engine.SignerClient,
				r.Engine.WriteTxnCallback(),
			),
		},
	}

	// Execute command via registry
	return registeredCmd.Handler.Execute(cmd.Args, ctx)
}
