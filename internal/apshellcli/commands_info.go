// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Info and status commands: help, status, accounts, balance, holders, participation, signers, quit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

func (r *REPLState) cmdHelp(args []string, _ interface{}) error {
	if len(args) == 0 {
		command.ShowHelp(r.Out, r.CommandRegistry)
		showPluginHelpSummary(r)
	} else {
		// Show detailed help for specific command
		cmd, ok := r.CommandRegistry.Lookup(args[0])
		if ok {
			command.ShowCommandHelp(r.Out, cmd)
			return nil
		}

		pluginCmd, err := findPluginHelpCommand(r, args[0])
		if err != nil {
			return err
		}
		command.ShowCommandHelp(r.Out, pluginCmd)
	}
	return nil
}

func showPluginHelpSummary(r *REPLState) {
	plugins, err := discoverExternalPlugins(r)
	if err != nil || len(plugins) == 0 {
		return
	}

	names := make([]string, 0, len(plugins))
	for _, plugin := range plugins {
		if len(plugin.Manifest.Commands) == 0 {
			continue
		}
		names = append(names, plugin.Manifest.Name)
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)

	r.println("\nPlugins:")
	for _, name := range names {
		r.printf("  %s\n", name)
	}
	r.println("\nFor plugin help, type: help <plugin>")
}

func findPluginHelpCommand(r *REPLState, name string) (*command.Command, error) {
	plugins, err := discoverExternalPlugins(r)
	if err != nil {
		return nil, fmt.Errorf("failed to discover plugins: %w", err)
	}

	type pluginMatch struct {
		plugin *discovery.Plugin
		cmd    manifest.Command
	}

	var matches []pluginMatch
	for _, plugin := range plugins {
		if cmd := plugin.Manifest.FindCommand(name); cmd != nil {
			matches = append(matches, pluginMatch{plugin: plugin, cmd: *cmd})
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("unknown command: %s", name)
	}
	if len(matches) > 1 {
		pluginNames := make([]string, len(matches))
		for i, match := range matches {
			pluginNames[i] = match.plugin.Manifest.Name
		}
		sort.Strings(pluginNames)
		return nil, fmt.Errorf("ambiguous plugin command %q provided by: %s", name, strings.Join(pluginNames, ", "))
	}

	return pluginHelpCommand(matches[0].plugin, matches[0].cmd), nil
}

func pluginHelpCommand(plugin *discovery.Plugin, pluginCmd manifest.Command) *command.Command {
	longHelpParts := make([]string, 0, 2)
	if len(pluginCmd.Examples) > 0 {
		longHelpParts = append(longHelpParts, "Examples:\n  "+strings.Join(pluginCmd.Examples, "\n  "))
	}
	if len(plugin.Manifest.Networks) > 0 {
		longHelpParts = append(longHelpParts, "Networks:\n  "+strings.Join(plugin.Manifest.Networks, ", "))
	}

	return &command.Command{
		Name:        pluginCmd.Name,
		Usage:       pluginCmd.Usage,
		Description: pluginCmd.Description,
		LongHelp:    strings.Join(longHelpParts, "\n\n"),
		Category:    "Plugin Commands",
		IsPlugin:    true,
	}
}

func (r *REPLState) cmdStatus(_ []string, _ interface{}) error {
	result, err := r.app().Status(r.commandContext())
	if err != nil {
		return err
	}

	// Provider info
	r.println("Providers:")
	r.printf("  LogicSig DSA: %v\n", result.LogicSigTypes)
	r.printf("  Algorithms:   %v\n", result.Algorithms)

	// Connection info
	r.println("Connection:")
	r.printf("  Network: %s\n", result.Status.Network)
	if result.Status.IsConnected {
		r.printf("  Signer: Connected (%s)\n", result.Status.ConnectionTarget)
	} else {
		r.println("  Signer: Not connected")
	}
	if result.TunnelConnected {
		r.println("  SSH Tunnel: Connected (public key)")
	} else {
		r.println("  SSH Tunnel: Not active")
	}

	// Cache info
	r.println("Cache:")
	r.printf("  ASA entries: %d\n", result.Status.ASACacheCount)
	r.printf("  Aliases: %d\n", result.Status.AliasCacheCount)
	if result.Status.SignerCacheCount > 0 {
		r.printf("  Remote keys: %d\n", result.Status.SignerCacheCount)
	}
	return nil
}

func (r *REPLState) cmdAccounts(_ []string, _ interface{}) error {
	result, err := r.app().Accounts(r.commandContext())
	if err != nil {
		return err
	}

	if len(result.Accounts) == 0 {
		r.println("No accounts found.")
		r.println("Add accounts with: alias <name> <address>")
		r.println("Or connect to Signer to see signer accounts")
		return nil
	}

	r.printf("Accounts (%d total):\n", len(result.Accounts))
	for _, acct := range result.Accounts {
		r.printf("  %s\n", r.app().FormatAddress(acct.Address, ""))
	}
	return nil
}

func (r *REPLState) cmdBalance(args []string, _ interface{}) error {
	res, err := r.app().Balance(r.commandContext(), apshellapp.BalanceRequest{Args: args})
	if err != nil {
		return err
	}

	switch res.Mode {
	case apshellapp.BalanceModeMulti:
		return r.showMultiAccountBalances(res.Addresses, res.AssetRef, false)
	case apshellapp.BalanceModeSingleFull:
		return r.showFullBalance(res.Single)
	case apshellapp.BalanceModeSingleAsset:
		return r.showSingleAssetBalance(res.Single, res.AssetRef)
	default:
		return fmt.Errorf("unsupported balance mode: %s", res.Mode)
	}
}

// cmdHolders shows accounts with non-zero balance of an asset
func (r *REPLState) cmdHolders(args []string, _ interface{}) error {
	result, err := r.app().Holders(r.commandContext(), args)
	if err != nil {
		return err
	}

	r.renderWarnings(result.Warnings)
	if len(result.Addresses) == 0 {
		r.println("No accounts with non-zero balance found")
		return nil
	}
	return r.showMultiAccountBalances(result.Addresses, result.AssetRef, true)
}

func (r *REPLState) cmdParticipation(args []string, _ interface{}) error {
	result, err := r.app().Participation(r.commandContext(), args)
	if err != nil {
		return err
	}

	participation := result.Participation

	r.printf("Account: %s\n", r.app().FormatAddress(participation.Address, ""))
	r.println()

	if result.IsRekeyed {
		r.printf("⚠️  Auth Address: %s (account is rekeyed)\n", r.app().FormatAddress(result.AuthAddress, ""))
		r.println()
	}

	r.println("Participation Status:")
	if participation.IsOnline {
		r.println("  Status: Online")
	} else {
		r.println("  Status: Offline")
	}
	r.println()

	r.println("Consensus Incentives:")
	if participation.IncentiveEligible {
		r.println("  Incentive Eligible: YES")
	} else {
		r.println("  Incentive Eligible: NO")
	}
	r.println()

	if participation.IsOnline && participation.VoteKey != "" {
		r.println("Participation Keys:")
		r.printf("  Vote Key: %s\n", participation.VoteKey)
		r.printf("  Selection Key: %s\n", participation.SelectionKey)
		if participation.StateProofKey != "" {
			r.printf("  State Proof Key: %s\n", participation.StateProofKey)
		}
		r.printf("  Valid Rounds: %d - %d\n", participation.VoteFirstValid, participation.VoteLastValid)
		r.printf("  Key Dilution: %d\n", participation.VoteKeyDilution)
	}
	return nil
}

func (r *REPLState) cmdSigners(_ []string, _ interface{}) error {
	result, err := execKeys(r)
	if err != nil {
		return err
	}
	result.RenderText(r.Out, r)
	return nil
}

// execKeys fetches keys from Signer and returns a KeysResult.
// Shared by REPL (text render) and MCP (JSON render).
// Returns all signable accounts (including aliases rekeyed to signer-controlled addresses).
func execKeys(r *REPLState) (*KeysResult, error) {
	result, err := r.app().Signers(r.commandContext())
	if err != nil {
		return nil, err
	}
	return &KeysResult{Keys: result.Keys}, nil
}

func (r *REPLState) cmdKeytypes(_ []string, _ interface{}) error {
	result, err := r.app().KeyTypes(r.commandContext())
	if err != nil {
		return err
	}

	if len(result.KeyTypes) == 0 {
		r.println("No key types available")
		return nil
	}

	for _, kt := range result.KeyTypes {
		r.printf("%s\t%s\n", keytypefmt.Display(kt.KeyType), kt.Description)
	}
	return nil
}

func (r *REPLState) cmdClear(_ []string, _ interface{}) error {
	r.print("\033[H\033[2J")
	return nil
}

func (r *REPLState) cmdQuit(_ []string, _ interface{}) error {
	r.println("Goodbye!")
	_ = disconnectTunnel(r) // Best-effort cleanup on exit
	return fmt.Errorf("exit")
}
