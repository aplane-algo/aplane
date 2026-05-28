// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Cache management methods for aliases and sets.
// Business logic for cache operations; UI/formatting is left to the REPL layer.
package engine

import (
	"context"
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/refname"
)

// HasAlias checks if a name is a defined alias.
func (e *Engine) HasAlias(name string) bool {
	name = refname.NormalizeAlias(name)
	return e.AliasCache.HasAlias(name)
}

// GetAliasForAddress returns the alias for a given address, or "" if none.
func (e *Engine) GetAliasForAddress(addr string) string {
	return e.AliasCache.GetAliasForAddress(addr)
}

// GetAuthAddress returns the cached auth address for an address.
func (e *Engine) GetAuthAddress(addr string) (string, bool) {
	return e.AuthCache.GetAuthAddress(addr)
}

func (e *Engine) withClientDataLock(fn func() error) error {
	return e.WithExclusiveLock(fn)
}

func (e *Engine) RefreshAuthAddressWithContext(ctx context.Context, addr string) (string, error) {
	if e.AlgodClient == nil {
		return "", ErrNoAlgodClient
	}
	return e.State.RefreshAuthAddressWithContext(ctx, addr)
}

// GetKeyType returns the signing algorithm for an address.
// Handles rekeyed aliases by looking up the auth address's key type.
func (e *Engine) GetKeyType(addr string) string {
	return e.getAlgorithm(addr)
}

// SignerKeyCount returns the number of keys in the signer cache.
func (e *Engine) SignerKeyCount() int {
	return e.signerCacheCount()
}

// ListRekeyedAccounts returns all rekeyed accounts from cache.
// Returns a list of (address, authAddress) pairs for accounts that are rekeyed.
func (e *Engine) ListRekeyedAccounts() []RekeyInfo {
	addressSet := e.collectAllAddresses()

	var result []RekeyInfo
	for addr := range addressSet {
		authAddr, exists := e.AuthCache.GetAuthAddress(addr)
		if !exists {
			continue
		}
		if authAddr != "" && authAddr != addr {
			result = append(result, RekeyInfo{
				Address:     addr,
				AuthAddress: authAddr,
			})
		}
	}
	return result
}

// RekeyInfo contains information about a rekeyed account.
type RekeyInfo struct {
	Address     string
	AuthAddress string
}

// AliasInfo contains information about a single alias.
type AliasInfo struct {
	Name       string
	Address    string
	IsSignable bool
	KeyType    string // "aplane.falcon1024.v1", "ed25519", or "" if not signable
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
		isSignable := e.isAccountSignable(address)
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
	name = refname.NormalizeAlias(name)
	if e.AliasCache.Aliases == nil {
		return nil
	}

	address, exists := e.AliasCache.Aliases[name]
	if !exists {
		return nil
	}

	isSignable := e.isAccountSignable(address)
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

func (e *Engine) AddAliasWithContext(ctx context.Context, name, address string) (*AddAliasResult, error) {
	name = refname.NormalizeAlias(name)
	mutation, err := e.State.AddAliasWithContext(ctx, name, address)
	if err != nil {
		return nil, err
	}
	result := &AddAliasResult{
		Name:       name,
		Address:    mutation.Address,
		WasUpdated: mutation.WasUpdated,
		OldAddress: mutation.OldAddress,
	}

	result.IsSignable = e.isAccountSignable(result.Address)
	if result.IsSignable {
		result.KeyType = e.getAlgorithm(result.Address)
	}

	return result, nil
}

// RemoveAlias removes an alias.
// Returns the address that was associated with the alias.
func (e *Engine) RemoveAlias(name string) (string, error) {
	name = refname.NormalizeAlias(name)
	address, found, err := e.State.RemoveAlias(name)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%w: %s", ErrAliasNotFound, name)
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
	name = refname.NormalizeSet(name)

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
	name = refname.NormalizeSet(name)

	mutation, err := e.State.AddSet(name, addressesOrAliases, e.NewAddressResolver().ResolveSingle)
	if err != nil {
		return nil, err
	}
	return &AddSetResult{
		Name:       name,
		Addresses:  mutation.Addresses,
		WasUpdated: mutation.WasUpdated,
		OldCount:   mutation.OldCount,
	}, nil
}

// RemoveSet removes a set.
// Returns the number of addresses that were in the set.
func (e *Engine) RemoveSet(name string) (int, error) {
	// Strip @ prefix if present
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}
	name = refname.NormalizeSet(name)

	count, found, err := e.State.RemoveSet(name)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("%w: @%s", ErrSetNotFound, name)
	}

	return count, nil
}

// AddToSet adds addresses to an existing set (or creates it if it doesn't exist).
func (e *Engine) AddToSet(name string, addressesOrAliases []string) (*AddSetResult, error) {
	// Strip @ prefix if present
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}
	name = refname.NormalizeSet(name)

	mutation, err := e.State.AddToSet(name, addressesOrAliases, e.NewAddressResolver().ResolveSingle)
	if err != nil {
		return nil, err
	}
	return &AddSetResult{
		Name:       name,
		Addresses:  mutation.Addresses,
		WasUpdated: mutation.WasUpdated,
		OldCount:   mutation.OldCount,
	}, nil
}

// RemoveFromSet removes addresses from a set.
func (e *Engine) RemoveFromSet(name string, addressesOrAliases []string) (*AddSetResult, error) {
	// Strip @ prefix if present
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}
	name = refname.NormalizeSet(name)

	mutation, found, err := e.State.RemoveFromSet(name, addressesOrAliases, e.NewAddressResolver().ResolveSingle)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: @%s", ErrSetNotFound, name)
	}
	return &AddSetResult{
		Name:       name,
		Addresses:  mutation.Addresses,
		WasUpdated: mutation.WasUpdated,
		OldCount:   mutation.OldCount,
	}, nil
}
