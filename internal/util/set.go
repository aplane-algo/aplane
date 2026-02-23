// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"sort"
)

// SetCache stores named collections of addresses
type SetCache struct {
	Sets map[string][]string `json:"sets"` // set name -> list of addresses
}

// LoadSetCache loads the set cache from disk with HMAC verification
func LoadSetCache() SetCache {
	cache := SetCache{Sets: make(map[string][]string)}
	if err := loadSignedCacheWithKey(getCachePath("set_cache.json"), &cache); err != nil {
		fmt.Printf("Warning: Failed to load set cache: %v\n", err)
	}
	return cache
}

// SaveCache saves the set cache to disk with HMAC signature
func (cache *SetCache) SaveCache() error {
	return saveSignedCacheWithKey(getCachePath("set_cache.json"), cache)
}

// CreateOrUpdateSet creates or updates a set with the given addresses
// Addresses are resolved from aliases before being stored
func (cache *SetCache) CreateOrUpdateSet(setName string, addresses []string, aliasCache *AliasCache) error {
	if setName == "" {
		return fmt.Errorf("set name cannot be empty")
	}

	if len(addresses) == 0 {
		return fmt.Errorf("set must contain at least one address")
	}

	// Resolve all addresses (convert aliases to addresses)
	resolvedAddresses := make([]string, 0, len(addresses))
	for _, addrOrAlias := range addresses {
		resolved, err := aliasCache.ResolveAddress(addrOrAlias)
		if err != nil {
			return fmt.Errorf("failed to resolve '%s': %w", addrOrAlias, err)
		}
		resolvedAddresses = append(resolvedAddresses, resolved)
	}

	// Check if set already exists
	if existing, exists := cache.Sets[setName]; exists {
		fmt.Printf("Updating set '%s' (was %d addresses, now %d addresses)\n", setName, len(existing), len(resolvedAddresses))
	} else {
		fmt.Printf("Creating new set '%s' with %d addresses\n", setName, len(resolvedAddresses))
	}

	cache.Sets[setName] = resolvedAddresses

	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save set cache: %w", err)
	}

	return nil
}

// AddToSet adds addresses to an existing set (or creates it if it doesn't exist)
func (cache *SetCache) AddToSet(setName string, addresses []string, aliasCache *AliasCache) error {
	if setName == "" {
		return fmt.Errorf("set name cannot be empty")
	}

	if len(addresses) == 0 {
		return fmt.Errorf("must provide at least one address to add")
	}

	// Resolve all addresses
	resolvedAddresses := make([]string, 0, len(addresses))
	for _, addrOrAlias := range addresses {
		resolved, err := aliasCache.ResolveAddress(addrOrAlias)
		if err != nil {
			return fmt.Errorf("failed to resolve '%s': %w", addrOrAlias, err)
		}
		resolvedAddresses = append(resolvedAddresses, resolved)
	}

	// Get existing set or create new one
	existing, exists := cache.Sets[setName]
	if !exists {
		existing = []string{}
	}

	// Add new addresses (avoiding duplicates)
	addedCount := 0
	for _, addr := range resolvedAddresses {
		// Check if already in set
		found := false
		for _, existingAddr := range existing {
			if existingAddr == addr {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, addr)
			addedCount++
		}
	}

	cache.Sets[setName] = existing

	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save set cache: %w", err)
	}

	fmt.Printf("Added %d addresses to set '%s' (now %d addresses total)\n", addedCount, setName, len(existing))
	return nil
}

// RemoveFromSet removes addresses from a set
func (cache *SetCache) RemoveFromSet(setName string, addresses []string, aliasCache *AliasCache) error {
	if setName == "" {
		return fmt.Errorf("set name cannot be empty")
	}

	existing, exists := cache.Sets[setName]
	if !exists {
		return fmt.Errorf("set '%s' does not exist", setName)
	}

	// Resolve addresses to remove
	toRemove := make(map[string]bool)
	for _, addrOrAlias := range addresses {
		resolved, err := aliasCache.ResolveAddress(addrOrAlias)
		if err != nil {
			return fmt.Errorf("failed to resolve '%s': %w", addrOrAlias, err)
		}
		toRemove[resolved] = true
	}

	// Filter out addresses to remove
	filtered := make([]string, 0)
	removedCount := 0
	for _, addr := range existing {
		if toRemove[addr] {
			removedCount++
		} else {
			filtered = append(filtered, addr)
		}
	}

	if len(filtered) == 0 {
		// Set is now empty, delete it
		delete(cache.Sets, setName)
		fmt.Printf("Set '%s' is now empty and has been deleted\n", setName)
	} else {
		cache.Sets[setName] = filtered
		fmt.Printf("Removed %d addresses from set '%s' (%d remaining)\n", removedCount, setName, len(filtered))
	}

	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save set cache: %w", err)
	}

	return nil
}

// DeleteSet deletes a set
func (cache *SetCache) DeleteSet(setName string) error {
	if _, exists := cache.Sets[setName]; !exists {
		return fmt.Errorf("set '%s' does not exist", setName)
	}

	delete(cache.Sets, setName)

	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save set cache: %w", err)
	}

	fmt.Printf("Deleted set '%s'\n", setName)
	return nil
}

// GetSet returns the addresses in a set
func (cache *SetCache) GetSet(setName string) ([]string, error) {
	addresses, exists := cache.Sets[setName]
	if !exists {
		return nil, fmt.Errorf("set '%s' does not exist", setName)
	}
	return addresses, nil
}

// ListSets lists all sets with their addresses
func (cache *SetCache) ListSets(aliasCache *AliasCache, signerCache *SignerCache, authCache *AuthAddressCache) {
	if len(cache.Sets) == 0 {
		fmt.Println("No sets defined")
		fmt.Println("Create a set with: set <name> [address1 address2 ...]")
		return
	}

	// Sort set names alphabetically
	names := make([]string, 0, len(cache.Sets))
	for name := range cache.Sets {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Printf("Defined sets (%d):\n\n", len(cache.Sets))
	for _, name := range names {
		addresses := cache.Sets[name]
		fmt.Printf("Set '%s' (%d addresses):\n", name, len(addresses))
		for i, addr := range addresses {
			// Use FormatAddress for proper coloring
			formatted := aliasCache.FormatAddress(addr, signerCache, authCache, "")
			fmt.Printf("  %d. %s\n", i+1, formatted)
		}
		fmt.Println()
	}
}

// ResolveAddressOrSet resolves either a single address/alias or a set name to a list of addresses
// If input starts with '@', it's treated as a set name
// Otherwise, it's treated as a single address/alias
func (cache *SetCache) ResolveAddressOrSet(input string, aliasCache *AliasCache) ([]string, error) {
	if len(input) > 0 && input[0] == '@' {
		// It's a set reference
		setName := input[1:]
		addresses, err := cache.GetSet(setName)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve set: %w", err)
		}
		return addresses, nil
	}

	// It's a single address/alias
	resolved, err := aliasCache.ResolveAddress(input)
	if err != nil {
		return nil, err
	}
	return []string{resolved}, nil
}
