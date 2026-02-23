// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Info and status commands: help, status, accounts, balance, holders, participation, signers, quit

import (
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/util"
)

func (r *REPLState) cmdHelp(args []string, _ interface{}) error {
	if len(args) == 0 {
		command.ShowHelp(r.CommandRegistry, r.Engine.Network)
	} else {
		// Show detailed help for specific command
		cmd, ok := r.CommandRegistry.Lookup(args[0])
		if !ok {
			return fmt.Errorf("unknown command: %s", args[0])
		}
		command.ShowCommandHelp(cmd)
	}
	return nil
}

func (r *REPLState) cmdStatus(_ []string, _ interface{}) error {
	result := r.Engine.GetStatus()

	// Provider info
	fmt.Println("Providers:")
	sigProviders := signing.GetRegisteredFamilies()
	fmt.Printf("  Signature:    %v\n", sigProviders)
	dsaTypes := logicsigdsa.GetKeyTypes()
	fmt.Printf("  LogicSig DSA: %v\n", dsaTypes)
	algorithms := algorithm.GetRegisteredFamilies()
	fmt.Printf("  Algorithms:   %v\n", algorithms)

	// Connection info
	fmt.Println("Connection:")
	fmt.Printf("  Network: %s\n", result.Network)
	if result.IsConnected {
		fmt.Printf("  Signer: Connected (%s)\n", result.ConnectionTarget)
	} else {
		fmt.Println("  Signer: Not connected")
	}
	if r.Engine.IsTunnelConnected() {
		fmt.Println("  SSH Tunnel: Connected (public key)")
	} else {
		fmt.Println("  SSH Tunnel: Not active")
	}

	// Cache info
	fmt.Println("Cache:")
	fmt.Printf("  ASA entries: %d\n", result.ASACacheCount)
	fmt.Printf("  Aliases: %d\n", result.AliasCacheCount)
	if result.SignerCacheCount > 0 {
		fmt.Printf("  Remote keys: %d\n", result.SignerCacheCount)
	}
	return nil
}

func (r *REPLState) cmdAccounts(_ []string, _ interface{}) error {
	accounts, err := r.Engine.ListAccounts()
	if err != nil {
		return err
	}

	if len(accounts) == 0 {
		fmt.Println("No accounts found.")
		fmt.Println("Add accounts with: alias <address> <name>")
		fmt.Println("Or connect to Signer to see signer accounts")
		return nil
	}

	fmt.Printf("Accounts (%d total):\n", len(accounts))
	for _, acct := range accounts {
		fmt.Printf("  %s\n", r.FormatAddress(acct.Address, ""))
	}
	return nil
}

func (r *REPLState) cmdBalance(args []string, _ interface{}) error {
	if len(args) > 2 {
		return fmt.Errorf("usage: balance [account|@all|@signers|@set] [asa|algo]")
	}

	// Default to @all with ALGO if no args specified
	account := "@all"
	assetRef := ""
	assetSpecified := false

	if len(args) >= 1 {
		// Check if first arg looks like an asset (not an account)
		// Assets don't start with @ and aren't 58-char addresses
		firstArg := args[0]
		if firstArg[0] != '@' && len(firstArg) != 58 && !r.Engine.AliasCache.HasAlias(firstArg) {
			// First arg is likely an asset, default account to @all
			assetRef = firstArg
			assetSpecified = true
		} else {
			account = firstArg
			if len(args) == 2 {
				assetRef = args[1]
				assetSpecified = true
			}
		}
	}

	// Handle @set references (e.g., @all, @signers, @mygroup)
	if len(account) > 0 && account[0] == '@' {
		resolver := r.NewAddressResolver()
		addresses, err := resolver.ResolveList([]string{account})
		if err != nil {
			return err
		}
		// For sets, default to algo if not specified
		if assetRef == "" {
			assetRef = "algo"
		}
		return r.showMultiAccountBalances(addresses, assetRef, false)
	}

	// Single account
	result, err := r.Engine.GetBalance(account)
	if err != nil {
		return err
	}

	// If no asset specified, show full balance (ALGO + all ASAs)
	if !assetSpecified {
		return r.showFullBalance(result)
	}

	// Show specific asset
	return r.showSingleAssetBalance(result, assetRef)
}

// cmdHolders shows accounts with non-zero balance of an asset
func (r *REPLState) cmdHolders(args []string, _ interface{}) error {
	assetRef := "algo"
	if len(args) > 1 {
		return fmt.Errorf("usage: holders [asa|algo]")
	}
	if len(args) == 1 {
		assetRef = args[0]
	}

	// Get all known addresses
	addresses := r.Engine.ListAllAddresses()
	if len(addresses) == 0 {
		return fmt.Errorf("no accounts found (add aliases or connect to signer)")
	}

	return r.showMultiAccountBalances(addresses, assetRef, true)
}

// showFullBalance shows ALGO + all ASA balances for an account
func (r *REPLState) showFullBalance(result *engine.BalanceResult) error {
	fmt.Printf("%s\n", r.FormatAddress(result.Address, ""))

	// Show ALGO balance
	algoBalance := float64(result.AlgoBalance) / 1000000.0
	fmt.Printf("  ALGO: %.6f\n", algoBalance)

	// Show all ASA balances
	if len(result.Assets) > 0 {
		for _, asset := range result.Assets {
			if asset.Amount > 0 {
				tokenBalance := formatAssetAmount(asset.Amount, asset.Decimals)
				unitName := asset.UnitName
				if unitName == "" {
					unitName = fmt.Sprintf("ASA#%d", asset.AssetID)
				}
				fmt.Printf("  %s: %.6f\n", unitName, tokenBalance)
			}
		}
	}

	return nil
}

// showSingleAssetBalance shows balance for a specific asset
func (r *REPLState) showSingleAssetBalance(result *engine.BalanceResult, assetRef string) error {
	isAlgo := assetRef == "algo" || assetRef == "ALGO"

	if isAlgo {
		algoBalance := float64(result.AlgoBalance) / 1000000.0
		fmt.Printf("%s: %.6f ALGO\n", r.FormatAddress(result.Address, ""), algoBalance)
		return nil
	}

	// Resolve ASA reference
	asaID, err := r.Engine.AsaCache.ResolveASAReference(assetRef, r.Engine.Network)
	if err != nil {
		return fmt.Errorf("unknown asset '%s': %w", assetRef, err)
	}

	// Find the asset in the account's holdings
	for _, asset := range result.Assets {
		if asset.AssetID == asaID {
			tokenBalance := formatAssetAmount(asset.Amount, asset.Decimals)
			unitName := asset.UnitName
			if unitName == "" {
				unitName = fmt.Sprintf("ASA#%d", asaID)
			}
			fmt.Printf("%s: %.6f %s\n", r.FormatAddress(result.Address, ""), tokenBalance, unitName)
			return nil
		}
	}

	// Account doesn't hold this asset
	fmt.Printf("%s: 0 %s (not opted in)\n", r.FormatAddress(result.Address, ""), assetRef)
	return nil
}

// showMultiAccountBalances shows balances across multiple accounts
// addresses: list of addresses to show balances for
// assetRef: optional asset filter (empty = ALGO)
// holdersOnly: if true, only show accounts with non-zero balance
func (r *REPLState) showMultiAccountBalances(addresses []string, assetRef string, holdersOnly bool) error {
	if len(addresses) == 0 {
		return fmt.Errorf("no accounts found")
	}

	// Dedupe addresses
	addressSet := make(map[string]bool)
	for _, addr := range addresses {
		addressSet[addr] = true
	}

	// Determine if filtering by specific asset
	isAlgo := assetRef == "" || assetRef == "algo" || assetRef == "ALGO"
	var asaID uint64
	var asaUnitName string
	var asaDecimals uint64

	if assetRef != "" && !isAlgo {
		var err error
		asaID, err = r.Engine.AsaCache.ResolveASAReference(assetRef, r.Engine.Network)
		if err != nil {
			return fmt.Errorf("unknown asset '%s': %w", assetRef, err)
		}
		asaInfo, err := r.Engine.GetASAInfo(asaID)
		if err != nil {
			return fmt.Errorf("failed to get ASA info: %w", err)
		}
		asaUnitName = asaInfo.UnitName
		asaDecimals = asaInfo.Decimals
	}

	// Fetch and display balances
	type accountBalance struct {
		name    string
		balance float64
	}
	var results []accountBalance
	var total float64

	for addr := range addressSet {
		result, err := r.Engine.GetBalance(addr)
		if err != nil {
			continue
		}

		var balance float64
		found := false

		if assetRef == "" {
			// No asset filter - show ALGO balance
			balance = float64(result.AlgoBalance) / 1000000.0
			found = true
		} else if isAlgo {
			balance = float64(result.AlgoBalance) / 1000000.0
			found = true
		} else {
			// Look for specific ASA
			for _, asset := range result.Assets {
				if asset.AssetID == asaID {
					balance = formatAssetAmount(asset.Amount, asaDecimals)
					found = true
					break
				}
			}
		}

		if found && (!holdersOnly || balance > 0) {
			results = append(results, accountBalance{
				name:    r.FormatAddress(addr, ""),
				balance: balance,
			})
			total += balance
		}
	}

	if len(results) == 0 {
		if holdersOnly {
			fmt.Println("No accounts with non-zero balance found")
		} else {
			fmt.Println("No accounts found")
		}
		return nil
	}

	// Sort by balance descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].balance > results[j].balance
	})

	// Print header
	unitName := "ALGO"
	if assetRef != "" && !isAlgo {
		unitName = asaUnitName
	}

	// Print balances
	for _, r := range results {
		fmt.Printf("%s: %.6f %s\n", r.name, r.balance, unitName)
	}

	fmt.Printf("\nTotal: %.6f %s across %d accounts\n", total, unitName, len(results))
	return nil
}

// formatAssetAmount formats an asset amount with decimals
func formatAssetAmount(amount uint64, decimals uint64) float64 {
	if decimals == 0 {
		return float64(amount)
	}
	divisor := 1.0
	for i := uint64(0); i < decimals; i++ {
		divisor *= 10.0
	}
	return float64(amount) / divisor
}

func (r *REPLState) cmdParticipation(args []string, _ interface{}) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: participation <address|alias>")
	}

	addressOrAlias := args[0]

	result, err := r.Engine.GetParticipationStatus(addressOrAlias)
	if err != nil {
		return err
	}

	fmt.Printf("Account: %s\n", r.FormatAddress(result.Address, ""))
	fmt.Println()

	isRekeyed, authAddr := r.Engine.IsRekeyed(result.Address)
	if isRekeyed {
		fmt.Printf("⚠️  Auth Address: %s (account is rekeyed)\n", r.FormatAddress(authAddr, ""))
		fmt.Println()
	}

	fmt.Println("Participation Status:")
	if result.IsOnline {
		fmt.Println("  Status: Online")
	} else {
		fmt.Println("  Status: Offline")
	}
	fmt.Println()

	fmt.Println("Consensus Incentives:")
	if result.IncentiveEligible {
		fmt.Println("  Incentive Eligible: YES")
	} else {
		fmt.Println("  Incentive Eligible: NO")
	}
	fmt.Println()

	if result.IsOnline && result.VoteKey != "" {
		fmt.Println("Participation Keys:")
		fmt.Printf("  Vote Key: %s\n", result.VoteKey)
		fmt.Printf("  Selection Key: %s\n", result.SelectionKey)
		if result.StateProofKey != "" {
			fmt.Printf("  State Proof Key: %s\n", result.StateProofKey)
		}
		fmt.Printf("  Valid Rounds: %d - %d\n", result.VoteFirstValid, result.VoteLastValid)
		fmt.Printf("  Key Dilution: %d\n", result.VoteKeyDilution)
	}
	return nil
}

func (r *REPLState) cmdSigners(_ []string, _ interface{}) error {
	if r.Engine.SignerClient == nil {
		fmt.Println("Not connected to Signer. Run 'connect host:port' first.")
		return nil
	}

	// Fetch from Signer with checksum for cache validation
	keysResp, err := r.Engine.SignerClient.GetKeys(r.Engine.SignerCache.Checksum)
	if err != nil {
		return fmt.Errorf("failed to fetch keys from Signer: %w", err)
	}

	if keysResp.Locked {
		fmt.Println("Signer is locked")
		return nil
	}

	// If cache is valid (304 Not Modified), just display existing cache
	if !keysResp.CacheValid {
		// Cache invalid or no checksum - rebuild from response
		r.Engine.SignerCache = util.NewSignerCache()
		r.populateSignerCacheFromKeys(keysResp.Keys)
		r.Engine.SignerCache.SetColorFormatter(algorithm.GetDisplayColor)
	}
	// Update checksum either way
	r.Engine.SignerCache.Checksum = keysResp.Checksum

	if r.Engine.SignerCache.Count() == 0 {
		fmt.Println("No signable accounts found")
		return nil
	}

	fmt.Printf("Signable accounts: %d\n\n", r.Engine.SignerCache.Count())
	signableAddresses := r.Engine.GetSignableAddresses()
	for i, address := range signableAddresses {
		fmt.Printf("%d. %s\n", i+1, r.FormatAddress(address, ""))
	}
	return nil
}

func (r *REPLState) cmdKeytypes(_ []string, _ interface{}) error {
	if r.Engine.SignerClient == nil {
		fmt.Println("Not connected to Signer. Run 'connect host:port' first.")
		return nil
	}

	resp, err := r.Engine.SignerClient.GetKeyTypes()
	if err != nil {
		return fmt.Errorf("failed to fetch key types from Signer: %w", err)
	}

	if len(resp.KeyTypes) == 0 {
		fmt.Println("No key types available")
		return nil
	}

	fmt.Printf("Available key types (%d):\n", len(resp.KeyTypes))
	for _, kt := range resp.KeyTypes {
		fmt.Println()
		fmt.Printf("  %s\n", kt.KeyType)
		if kt.Description != "" {
			fmt.Printf("    %s\n", kt.Description)
		}
		if kt.MnemonicWordCount > 0 {
			fmt.Printf("    Mnemonic: %d words (%s)\n", kt.MnemonicWordCount, kt.MnemonicScheme)
		}
		if len(kt.CreationParams) > 0 {
			fmt.Printf("    Creation params:\n")
			for _, p := range kt.CreationParams {
				req := "optional"
				if p.Required {
					req = "required"
				}
				desc := ""
				if p.Description != "" {
					desc = " - " + p.Description
				}
				fmt.Printf("      %s (%s, %s)%s\n", p.Name, p.Type, req, desc)
			}
		}
		if len(kt.RuntimeArgs) > 0 {
			fmt.Printf("    Runtime args:\n")
			for _, a := range kt.RuntimeArgs {
				req := "optional"
				if a.Required {
					req = "required"
				}
				desc := ""
				if a.Description != "" {
					desc = " - " + a.Description
				}
				fmt.Printf("      %s (%s, %s)%s\n", a.Name, a.Type, req, desc)
			}
		}
	}
	return nil
}

func (r *REPLState) cmdQuit(_ []string, _ interface{}) error {
	fmt.Println("Goodbye!")
	_ = r.disconnectTunnel() // Best-effort cleanup on exit
	return fmt.Errorf("exit")
}
