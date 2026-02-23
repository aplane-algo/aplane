// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package engine cache management methods for aliases and sets.
// These methods provide business logic for cache operations while
// leaving UI/formatting to the REPL layer.
package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/util"
)

// AliasInfo contains information about a single alias.
type AliasInfo struct {
	Name       string
	Address    string
	IsSignable bool
	KeyType    string // "falcon1024-v1", "ed25519", or "" if not signable
}

// AliasListResult contains the result of listing aliases.
type AliasListResult struct {
	Aliases []AliasInfo
}

// ListAliases returns all defined aliases with their signability status.
func (e *Engine) ListAliases() *AliasListResult {
	result := &AliasListResult{
		Aliases: make([]AliasInfo, 0),
	}

	if e.AliasCache.Aliases == nil {
		return result
	}

	// Extract and sort alias names alphabetically
	names := make([]string, 0, len(e.AliasCache.Aliases))
	for name := range e.AliasCache.Aliases {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		address := e.AliasCache.Aliases[name]
		isSignable := util.IsAccountSignable(address, &e.SignerCache, &e.AuthCache)
		keyType := ""
		if isSignable {
			keyType = e.getAlgorithm(address)
		}

		result.Aliases = append(result.Aliases, AliasInfo{
			Name:       name,
			Address:    address,
			IsSignable: isSignable,
			KeyType:    keyType,
		})
	}

	return result
}

// GetAlias returns information about a specific alias.
// Returns nil if the alias doesn't exist.
func (e *Engine) GetAlias(name string) *AliasInfo {
	if e.AliasCache.Aliases == nil {
		return nil
	}

	address, exists := e.AliasCache.Aliases[name]
	if !exists {
		return nil
	}

	isSignable := util.IsAccountSignable(address, &e.SignerCache, &e.AuthCache)
	keyType := ""
	if isSignable {
		keyType = e.getAlgorithm(address)
	}

	return &AliasInfo{
		Name:       name,
		Address:    address,
		IsSignable: isSignable,
		KeyType:    keyType,
	}
}

// AddAliasResult contains the result of adding an alias.
type AddAliasResult struct {
	Name       string
	Address    string
	WasUpdated bool   // True if alias existed and was updated
	OldAddress string // Previous address if updated
	IsSignable bool
	KeyType    string
}

// AddAlias adds or updates an alias.
// Address must be a valid 58-character Algorand address.
func (e *Engine) AddAlias(name, address string) (*AddAliasResult, error) {
	// Validate and normalize address to uppercase (uppercase before decode for case-insensitive input)
	decoded, err := types.DecodeAddress(strings.ToUpper(address))
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	address = decoded.String() // Normalize to uppercase

	result := &AddAliasResult{
		Name:    name,
		Address: address,
	}

	// Check if alias already exists
	if e.AliasCache.Aliases == nil {
		e.AliasCache.Aliases = make(map[string]string)
	}

	// Check if address already has a different alias
	if existingAlias := e.AliasCache.GetAliasForAddress(address); existingAlias != "" && existingAlias != name {
		return nil, fmt.Errorf("address already has alias '%s'", existingAlias)
	}

	if oldAddr, exists := e.AliasCache.Aliases[name]; exists {
		if oldAddr == address {
			// Already points to same address
			result.IsSignable = util.IsAccountSignable(address, &e.SignerCache, &e.AuthCache)
			if result.IsSignable {
				result.KeyType = e.getAlgorithm(address)
			}
			return result, nil
		}
		result.WasUpdated = true
		result.OldAddress = oldAddr
	}

	// Add/update the alias
	e.AliasCache.Aliases[name] = address

	// Save cache
	if err := e.AliasCache.SaveCache(); err != nil {
		return nil, fmt.Errorf("failed to save alias cache: %w", err)
	}

	// Update auth cache for the new address if we have algod client
	if e.AlgodClient != nil {
		acctInfo, err := e.AlgodClient.AccountInformation(address).Do(context.Background())
		if err == nil {
			// Ignore disk write errors - best effort
			_ = e.AuthCache.UpdateAuthAddress(address, acctInfo.AuthAddr, e.Network)
		}
	}

	result.IsSignable = util.IsAccountSignable(address, &e.SignerCache, &e.AuthCache)
	if result.IsSignable {
		result.KeyType = e.getAlgorithm(address)
	}

	return result, nil
}

// RemoveAlias removes an alias.
// Returns the address that was associated with the alias.
func (e *Engine) RemoveAlias(name string) (string, error) {
	if e.AliasCache.Aliases == nil {
		return "", fmt.Errorf("alias '%s' does not exist", name)
	}

	address, exists := e.AliasCache.Aliases[name]
	if !exists {
		return "", fmt.Errorf("alias '%s' does not exist", name)
	}

	delete(e.AliasCache.Aliases, name)

	if err := e.AliasCache.SaveCache(); err != nil {
		return "", fmt.Errorf("failed to save alias cache: %w", err)
	}

	return address, nil
}

// SetInfo contains information about a single set.
type SetInfo struct {
	Name      string
	Addresses []string
	Count     int
}

// SetListResult contains the result of listing sets.
type SetListResult struct {
	Sets []SetInfo
}

// ListSets returns all defined sets.
func (e *Engine) ListSets() *SetListResult {
	result := &SetListResult{
		Sets: make([]SetInfo, 0),
	}

	if e.SetCache.Sets == nil {
		return result
	}

	// Extract and sort set names alphabetically
	names := make([]string, 0, len(e.SetCache.Sets))
	for name := range e.SetCache.Sets {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		addresses := e.SetCache.Sets[name]
		result.Sets = append(result.Sets, SetInfo{
			Name:      name,
			Addresses: addresses,
			Count:     len(addresses),
		})
	}

	return result
}

// GetSet returns information about a specific set.
// Returns nil if the set doesn't exist.
func (e *Engine) GetSet(name string) *SetInfo {
	if e.SetCache.Sets == nil {
		return nil
	}

	// Strip @ prefix if present
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}

	addresses, exists := e.SetCache.Sets[name]
	if !exists {
		return nil
	}

	return &SetInfo{
		Name:      name,
		Addresses: addresses,
		Count:     len(addresses),
	}
}

// AddSetResult contains the result of adding/updating a set.
type AddSetResult struct {
	Name       string
	Addresses  []string
	WasUpdated bool
	OldCount   int
}

// AddSet creates or replaces a set with the given addresses.
// Addresses can be aliases or raw addresses - they will be resolved.
func (e *Engine) AddSet(name string, addressesOrAliases []string) (*AddSetResult, error) {
	// Strip @ prefix if present
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}

	// Check for reserved names
	if util.IsReservedSetName(name) {
		return nil, fmt.Errorf("'%s' is a reserved set name and cannot be used", name)
	}

	// Resolve all addresses
	resolver := e.NewAddressResolver()
	resolvedAddresses := make([]string, 0, len(addressesOrAliases))

	for _, input := range addressesOrAliases {
		addr, err := resolver.ResolveSingle(input)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve '%s': %w", input, err)
		}
		resolvedAddresses = append(resolvedAddresses, addr)
	}

	result := &AddSetResult{
		Name:      name,
		Addresses: resolvedAddresses,
	}

	// Check if set exists
	if e.SetCache.Sets == nil {
		e.SetCache.Sets = make(map[string][]string)
	}

	if oldAddrs, exists := e.SetCache.Sets[name]; exists {
		result.WasUpdated = true
		result.OldCount = len(oldAddrs)
	}

	// Add/update the set
	e.SetCache.Sets[name] = resolvedAddresses

	// Save cache
	if err := e.SetCache.SaveCache(); err != nil {
		return nil, fmt.Errorf("failed to save set cache: %w", err)
	}

	return result, nil
}

// RemoveSet removes a set.
// Returns the number of addresses that were in the set.
func (e *Engine) RemoveSet(name string) (int, error) {
	// Strip @ prefix if present
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}

	if e.SetCache.Sets == nil {
		return 0, fmt.Errorf("set '@%s' does not exist", name)
	}

	addresses, exists := e.SetCache.Sets[name]
	if !exists {
		return 0, fmt.Errorf("set '@%s' does not exist", name)
	}

	count := len(addresses)
	delete(e.SetCache.Sets, name)

	if err := e.SetCache.SaveCache(); err != nil {
		return 0, fmt.Errorf("failed to save set cache: %w", err)
	}

	return count, nil
}

// AddToSet adds addresses to an existing set (or creates it if it doesn't exist).
func (e *Engine) AddToSet(name string, addressesOrAliases []string) (*AddSetResult, error) {
	// Strip @ prefix if present
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}

	// Check for reserved names
	if util.IsReservedSetName(name) {
		return nil, fmt.Errorf("'%s' is a reserved set name and cannot be used", name)
	}

	// Resolve new addresses
	resolver := e.NewAddressResolver()
	newAddresses := make([]string, 0, len(addressesOrAliases))

	for _, input := range addressesOrAliases {
		addr, err := resolver.ResolveSingle(input)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve '%s': %w", input, err)
		}
		newAddresses = append(newAddresses, addr)
	}

	// Get existing addresses
	if e.SetCache.Sets == nil {
		e.SetCache.Sets = make(map[string][]string)
	}

	existingAddresses := e.SetCache.Sets[name]
	result := &AddSetResult{
		Name:       name,
		WasUpdated: len(existingAddresses) > 0,
		OldCount:   len(existingAddresses),
	}

	// Merge addresses (avoid duplicates)
	addressSet := make(map[string]bool)
	for _, addr := range existingAddresses {
		addressSet[addr] = true
	}
	for _, addr := range newAddresses {
		addressSet[addr] = true
	}

	mergedAddresses := make([]string, 0, len(addressSet))
	for addr := range addressSet {
		mergedAddresses = append(mergedAddresses, addr)
	}
	sort.Strings(mergedAddresses)

	e.SetCache.Sets[name] = mergedAddresses
	result.Addresses = mergedAddresses

	if err := e.SetCache.SaveCache(); err != nil {
		return nil, fmt.Errorf("failed to save set cache: %w", err)
	}

	return result, nil
}

// RemoveFromSet removes addresses from a set.
func (e *Engine) RemoveFromSet(name string, addressesOrAliases []string) (*AddSetResult, error) {
	// Strip @ prefix if present
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}

	if e.SetCache.Sets == nil {
		return nil, fmt.Errorf("set '@%s' does not exist", name)
	}

	existingAddresses, exists := e.SetCache.Sets[name]
	if !exists {
		return nil, fmt.Errorf("set '@%s' does not exist", name)
	}

	// Resolve addresses to remove
	resolver := e.NewAddressResolver()
	toRemove := make(map[string]bool)

	for _, input := range addressesOrAliases {
		addr, err := resolver.ResolveSingle(input)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve '%s': %w", input, err)
		}
		toRemove[addr] = true
	}

	// Filter out addresses to remove
	remainingAddresses := make([]string, 0)
	for _, addr := range existingAddresses {
		if !toRemove[addr] {
			remainingAddresses = append(remainingAddresses, addr)
		}
	}

	result := &AddSetResult{
		Name:       name,
		Addresses:  remainingAddresses,
		WasUpdated: true,
		OldCount:   len(existingAddresses),
	}

	e.SetCache.Sets[name] = remainingAddresses

	if err := e.SetCache.SaveCache(); err != nil {
		return nil, fmt.Errorf("failed to save set cache: %w", err)
	}

	return result, nil
}
