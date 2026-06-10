// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"sort"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
)

// GetStatus returns the current engine status as structured data
func (e *Engine) GetStatus() *StatusResult {
	e.Connection.Mu.Lock()
	signingMode := "disconnected"
	if e.Connection.TunnelConnected {
		signingMode = "remote"
	} else if e.Connection.SignerClient != nil {
		signingMode = "local"
	}
	isConnected := e.Connection.TunnelConnected || e.Connection.SignerClient != nil
	connectionTarget := e.Connection.ConnectionTarget
	e.Connection.Mu.Unlock()

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

	return &StatusResult{
		Network:          e.Network,
		IsConnected:      isConnected,
		ConnectionTarget: connectionTarget,
		SigningMode:      signingMode,
		WriteMode:        e.WriteMode,
		ASACacheCount:    asaCacheCount,
		AliasCacheCount:  aliasCacheCount,
		SetCacheCount:    setCacheCount,
		SignerCacheCount: e.signerCacheCount(),
	}
}

func (e *Engine) GetBalance(ctx context.Context, addressOrAlias string) (*BalanceResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Resolve alias to address
	address, err := e.AliasCache.ResolveAddress(addressOrAlias)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAddress, addressOrAlias)
	}

	// Query algod for account info
	accountInfo, err := e.AlgodClient.AccountInformation(address).Do(ctx)
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

		// Resolve metadata through the shared ASA system.
		if meta, err := e.ASAResolver().MetadataByID(holding.AssetId); err == nil && meta.Source != asa.SourceIDOnly {
			ab.UnitName = meta.UnitName
			ab.Decimals = meta.Decimals
		}

		result.Assets = append(result.Assets, ab)
	}

	return result, nil
}

func (e *Engine) GetAccountBalanceRaw(ctx context.Context, address string) (*BalanceResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Query algod for account info (no alias resolution)
	accountInfo, err := e.AlgodClient.AccountInformation(address).Do(ctx)
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

		// Resolve metadata through the shared ASA system.
		if meta, err := e.ASAResolver().MetadataByID(holding.AssetId); err == nil && meta.Source != asa.SourceIDOnly {
			ab.UnitName = meta.UnitName
			ab.Decimals = meta.Decimals
		}

		result.Assets = append(result.Assets, ab)
	}

	return result, nil
}

func (e *Engine) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}

	keysResp, err := e.GetKeysWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var result []KeyInfo
	for _, k := range keysResp.Keys {
		result = append(result, KeyInfo{
			Address:                  k.Address,
			KeyType:                  k.KeyType,
			PublicKeyHex:             k.PublicKeyHex,
			Parameters:               maps.Clone(k.Parameters),
			TemplateProvenanceStatus: k.TemplateProvenanceStatus,
			TemplateProvenanceNote:   k.TemplateProvenanceNote,
		})
	}
	return result, nil
}

func (e *Engine) RefreshKeys(ctx context.Context) ([]KeyInfo, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	keysResp, err := e.GetKeysWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keys: %w", err)
	}
	if keysResp.Locked {
		return nil, ErrSignerLocked
	}
	// Rebuild signer cache
	if err := e.withClientDataLock(func() error {
		return e.populateAndSaveSignerCacheUnderClientLock(keysResp.Keys)
	}); err != nil {
		cache.Debug("failed to save signer cache", "error", err)
		e.populateSignerCache(keysResp.Keys)
	}
	// Build result
	var result []KeyInfo
	for _, k := range keysResp.Keys {
		result = append(result, KeyInfo{
			Address:                  k.Address,
			KeyType:                  k.KeyType,
			PublicKeyHex:             k.PublicKeyHex,
			Parameters:               maps.Clone(k.Parameters),
			TemplateProvenanceStatus: k.TemplateProvenanceStatus,
			TemplateProvenanceNote:   k.TemplateProvenanceNote,
		})
	}
	return result, nil
}

// ListSigners returns addresses we can actually sign for.
// This includes:
// - Signer addresses that are NOT rekeyed away
// - Alias addresses that ARE rekeyed TO a signer we control
// Returns a map of address -> key type (e.g., "ed25519", "aplane.falcon1024.v1").
func (e *Engine) listSignersCached() map[string]string {
	result := make(map[string]string)

	addressSet := e.collectAllAddresses()

	// Filter to only addresses we can actually sign for
	for addr := range addressSet {
		if e.isSignable(addr) {
			result[addr] = e.getAlgorithm(addr)
		}
	}

	return result
}

// ListSigners returns addresses we can actually sign for.
func (e *Engine) ListSigners() (map[string]string, error) {
	if err := e.EnsureSignerCache(context.Background()); err != nil {
		return nil, err
	}
	return e.listSignersCached(), nil
}

// ListAccounts returns all known accounts (aliases + signable addresses)
func (e *Engine) ListAccounts() ([]AccountInfo, error) {
	addressSet := e.collectAllAddresses()

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
	addressSet := e.collectAllAddresses()

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

// HoldersResult returns addresses with non-zero balance plus query diagnostics.
type HoldersResult struct {
	Addresses   []string
	QueryErrors int
}

// GetHolders returns addresses with non-zero balance of the specified asset.
// assetRef can be "algo", an ASA ID, or an ASA unit name.
func (e *Engine) GetHolders(ctx context.Context, assetRef string) (*HoldersResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Get all known addresses
	addresses, err := e.ListAllAddresses()
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no accounts found")
	}

	// Determine if checking ALGO or ASA
	isAlgo := assetRef == "" || assetRef == "algo" || assetRef == "ALGO"
	var asaID uint64

	if !isAlgo {
		var err error
		asaID, err = e.ResolveASAReference(assetRef)
		if err != nil {
			return nil, fmt.Errorf("unknown asset '%s': %w", assetRef, err)
		}
	}

	// Check each address for non-zero balance
	var holders []string
	var queryErrors int
	for _, addr := range addresses {
		result, err := e.GetAccountBalanceRaw(ctx, addr)
		if err != nil {
			queryErrors++
			continue
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

	return &HoldersResult{Addresses: holders, QueryErrors: queryErrors}, nil
}

// GetParticipationStatus returns the consensus participation status for an address
func (e *Engine) GetParticipationStatus(ctx context.Context, addressOrAlias string) (*ParticipationResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Resolve alias to address
	address, err := e.AliasCache.ResolveAddress(addressOrAlias)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAddress, addressOrAlias)
	}

	// Query algod for account info
	accountInfo, err := e.AlgodClient.AccountInformation(address).Do(ctx)
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
	return e.isAccountSignable(address)
}

// getAlgorithm returns the signing algorithm for an address
func (e *Engine) getAlgorithm(address string) string {
	authAddr, authExists := e.AuthCache.GetAuthAddress(address)

	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()

	// Check signer cache for key type
	if e.SignerCache.Keys != nil {
		if keyType, exists := e.SignerCache.Keys[address]; exists {
			return keyType
		}
	}

	// Check if rekeyed, and if so, get the auth address's key type
	if authExists && authAddr != "" {
		if e.SignerCache.Keys != nil {
			if keyType, exists := e.SignerCache.Keys[authAddr]; exists {
				return keyType
			}
		}
	}

	return "unknown"
}
