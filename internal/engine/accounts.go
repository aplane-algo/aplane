// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/util"
)

// GetStatus returns the current engine status as structured data
func (e *Engine) GetStatus() *StatusResult {
	e.connMu.Lock()
	defer e.connMu.Unlock()

	signingMode := "disconnected"
	if e.tunnelConnected {
		signingMode = "remote"
	} else if e.SignerClient != nil {
		signingMode = "local"
	}

	asaCacheCount := 0
	if e.AsaCache.Assets != nil {
		asaCacheCount = len(e.AsaCache.Assets)
	}

	aliasCacheCount := 0
	if e.AliasCache.Aliases != nil {
		aliasCacheCount = len(e.AliasCache.Aliases)
	}

	setCacheCount := 0
	if e.SetCache.Sets != nil {
		setCacheCount = len(e.SetCache.Sets)
	}

	signerCacheCount := 0
	if e.SignerCache.Keys != nil {
		signerCacheCount = len(e.SignerCache.Keys)
	}

	return &StatusResult{
		Network:          e.Network,
		IsConnected:      e.tunnelConnected || e.SignerClient != nil,
		ConnectionTarget: e.connectionTarget,
		SigningMode:      signingMode,
		WriteMode:        e.WriteMode,
		ASACacheCount:    asaCacheCount,
		AliasCacheCount:  aliasCacheCount,
		SetCacheCount:    setCacheCount,
		SignerCacheCount: signerCacheCount,
	}
}

// GetBalance returns balance information for an address or alias
func (e *Engine) GetBalance(addressOrAlias string) (*BalanceResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Resolve alias to address
	address, err := e.AliasCache.ResolveAddress(addressOrAlias)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAddress, addressOrAlias)
	}

	// Query algod for account info
	accountInfo, err := e.AlgodClient.AccountInformation(address).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get account info: %w", err)
	}

	// Build result
	result := &BalanceResult{
		Address:     address,
		Alias:       e.AliasCache.GetAliasForAddress(address),
		AlgoBalance: accountInfo.Amount,
		MinBalance:  accountInfo.MinBalance,
		AuthAddr:    accountInfo.AuthAddr,
	}

	// Process assets
	for _, holding := range accountInfo.Assets {
		ab := AssetBalance{
			AssetID:   holding.AssetId,
			Amount:    holding.Amount,
			IsFrozen:  holding.IsFrozen,
			IsOptedIn: true,
		}

		// Get asset info from cache, or fetch from network on miss
		if asaInfo, err := e.AsaCache.GetASAInfo(e.AlgodClient, holding.AssetId, e.Network); err == nil {
			ab.UnitName = asaInfo.UnitName
			ab.Decimals = asaInfo.Decimals
		}

		result.Assets = append(result.Assets, ab)
	}

	return result, nil
}

// GetAccountBalanceRaw returns raw balance for a pre-resolved address.
// Address must be a 58-character Algorand address (no aliases).
// Returns ALGO balance in microAlgos and ASA balances in base units.
func (e *Engine) GetAccountBalanceRaw(address string) (*BalanceResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Query algod for account info (no alias resolution)
	accountInfo, err := e.AlgodClient.AccountInformation(address).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get account info: %w", err)
	}

	// Build result
	result := &BalanceResult{
		Address:     address,
		AlgoBalance: accountInfo.Amount,
		MinBalance:  accountInfo.MinBalance,
		AuthAddr:    accountInfo.AuthAddr,
	}

	// Process assets
	for _, holding := range accountInfo.Assets {
		ab := AssetBalance{
			AssetID:   holding.AssetId,
			Amount:    holding.Amount,
			IsFrozen:  holding.IsFrozen,
			IsOptedIn: true,
		}

		// Get asset info from cache, or fetch from network on miss
		if asaInfo, err := e.AsaCache.GetASAInfo(e.AlgodClient, holding.AssetId, e.Network); err == nil {
			ab.UnitName = asaInfo.UnitName
			ab.Decimals = asaInfo.Decimals
		}

		result.Assets = append(result.Assets, ab)
	}

	return result, nil
}

// ListKeys returns all remote signing keys from Signer
func (e *Engine) ListKeys() ([]KeyInfo, error) {
	if e.SignerClient == nil {
		return nil, ErrNotConnected
	}

	keysResp, err := e.SignerClient.GetKeys("")
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var result []KeyInfo
	for _, k := range keysResp.Keys {
		result = append(result, KeyInfo{
			Address:      k.Address,
			KeyType:      k.KeyType,
			PublicKeyHex: k.PublicKeyHex,
		})
	}
	return result, nil
}

// ListSigners returns addresses we can actually sign for.
// This includes:
// - Signer addresses that are NOT rekeyed away
// - Alias addresses that ARE rekeyed TO a signer we control
// Returns a map of address -> key type (e.g., "ed25519", "falcon1024-v1").
func (e *Engine) ListSigners() map[string]string {
	// Auto-refresh SignerCache if connected but cache is empty
	e.EnsureSignerCache()

	result := make(map[string]string)

	// Collect all known addresses (signers + aliases)
	addressSet := make(map[string]bool)
	if e.SignerCache.Keys != nil {
		for addr := range e.SignerCache.Keys {
			addressSet[addr] = true
		}
	}
	if e.AliasCache.Aliases != nil {
		for _, addr := range e.AliasCache.Aliases {
			addressSet[addr] = true
		}
	}

	// Filter to only addresses we can actually sign for
	for addr := range addressSet {
		if e.isSignable(addr) {
			result[addr] = e.getAlgorithm(addr)
		}
	}

	return result
}

// ListAccounts returns all known accounts (aliases + signable addresses)
func (e *Engine) ListAccounts() ([]AccountInfo, error) {
	addressSet := make(map[string]bool)

	// Add all aliases
	if e.AliasCache.Aliases != nil {
		for _, addr := range e.AliasCache.Aliases {
			addressSet[addr] = true
		}
	}

	// Add all signer addresses
	if e.SignerCache.Keys != nil {
		for addr := range e.SignerCache.Keys {
			addressSet[addr] = true
		}
	}

	// Convert to sorted slice
	addresses := make([]string, 0, len(addressSet))
	for addr := range addressSet {
		addresses = append(addresses, addr)
	}
	sort.Strings(addresses)

	// Build result
	var accounts []AccountInfo
	for _, addr := range addresses {
		isSignable := e.isSignable(addr)
		algo := ""
		if isSignable {
			algo = e.getAlgorithm(addr)
		}

		source := "signer"
		alias := e.AliasCache.GetAliasForAddress(addr)
		if alias != "" {
			source = "alias"
		}

		accounts = append(accounts, AccountInfo{
			Address:    addr,
			Alias:      alias,
			Source:     source,
			IsSignable: isSignable,
			KeyType:    algo,
		})
	}

	return accounts, nil
}

// GetSignableAddresses returns a list of all addresses that can be signed for
func (e *Engine) GetSignableAddresses() []string {
	addressSet := make(map[string]bool)

	// Add all keys from Signer
	if e.SignerCache.Keys != nil {
		for addr := range e.SignerCache.Keys {
			addressSet[addr] = true
		}
	}

	// Add all aliases
	if e.AliasCache.Aliases != nil {
		for _, addr := range e.AliasCache.Aliases {
			addressSet[addr] = true
		}
	}

	// Filter to only signable addresses
	var signableAddresses []string
	for addr := range addressSet {
		if e.isSignable(addr) {
			signableAddresses = append(signableAddresses, addr)
		}
	}

	sort.Strings(signableAddresses)
	return signableAddresses
}

// GetHolders returns addresses with non-zero balance of the specified asset.
// assetRef can be "algo", an ASA ID, or an ASA unit name.
// Returns a list of addresses that hold the asset.
func (e *Engine) GetHolders(assetRef string) ([]string, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Get all known addresses
	addresses := e.ListAllAddresses()
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no accounts found")
	}

	// Determine if checking ALGO or ASA
	isAlgo := assetRef == "" || assetRef == "algo" || assetRef == "ALGO"
	var asaID uint64

	if !isAlgo {
		var err error
		asaID, err = e.AsaCache.ResolveASAReference(assetRef, e.Network)
		if err != nil {
			return nil, fmt.Errorf("unknown asset '%s': %w", assetRef, err)
		}
	}

	// Check each address for non-zero balance
	var holders []string
	for _, addr := range addresses {
		result, err := e.GetAccountBalanceRaw(addr)
		if err != nil {
			continue // Skip accounts that fail to query
		}

		if isAlgo {
			if result.AlgoBalance > 0 {
				holders = append(holders, addr)
			}
		} else {
			for _, asset := range result.Assets {
				if asset.AssetID == asaID && asset.Amount > 0 {
					holders = append(holders, addr)
					break
				}
			}
		}
	}

	return holders, nil
}

// GetParticipationStatus returns the consensus participation status for an address
func (e *Engine) GetParticipationStatus(addressOrAlias string) (*ParticipationResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Resolve alias to address
	address, err := e.AliasCache.ResolveAddress(addressOrAlias)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAddress, addressOrAlias)
	}

	// Query algod for account info
	accountInfo, err := e.AlgodClient.AccountInformation(address).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get account info: %w", err)
	}

	result := &ParticipationResult{
		Address:           address,
		IsOnline:          accountInfo.Status == "Online",
		IncentiveEligible: accountInfo.IncentiveEligible,
	}

	// Extract participation keys if online
	if result.IsOnline && len(accountInfo.Participation.VoteParticipationKey) > 0 {
		result.VoteKey = base64.StdEncoding.EncodeToString(accountInfo.Participation.VoteParticipationKey)
		result.SelectionKey = base64.StdEncoding.EncodeToString(accountInfo.Participation.SelectionParticipationKey)
		if len(accountInfo.Participation.StateProofKey) > 0 {
			result.StateProofKey = base64.StdEncoding.EncodeToString(accountInfo.Participation.StateProofKey)
		}
		result.VoteFirstValid = accountInfo.Participation.VoteFirstValid
		result.VoteLastValid = accountInfo.Participation.VoteLastValid
		result.VoteKeyDilution = accountInfo.Participation.VoteKeyDilution
	}

	return result, nil
}

// ResolveAddress resolves an alias or address to an address and returns both
func (e *Engine) ResolveAddress(addressOrAlias string) (address, alias string, err error) {
	resolved, err := e.AliasCache.ResolveAddress(addressOrAlias)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", ErrInvalidAddress, addressOrAlias)
	}

	foundAlias := e.AliasCache.GetAliasForAddress(resolved)
	return resolved, foundAlias, nil
}

// isSignable checks if an address can be signed for
func (e *Engine) isSignable(address string) bool {
	return util.IsAccountSignable(address, &e.SignerCache, &e.AuthCache)
}

// getAlgorithm returns the signing algorithm for an address
func (e *Engine) getAlgorithm(address string) string {
	// Check signer cache for key type
	if e.SignerCache.Keys != nil {
		if keyType, exists := e.SignerCache.Keys[address]; exists {
			return keyType
		}
	}

	// Check if rekeyed, and if so, get the auth address's key type
	if e.AuthCache.AuthAddresses != nil {
		if authAddr, exists := e.AuthCache.AuthAddresses[address]; exists && authAddr != "" {
			if e.SignerCache.Keys != nil {
				if keyType, exists := e.SignerCache.Keys[authAddr]; exists {
					return keyType
				}
			}
		}
	}

	return "unknown"
}
