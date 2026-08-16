// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/refname"
)

// SetCache stores named collections of addresses
type SetCache struct {
	SchemaVersion int                 `json:"schema_version,omitempty"`
	Sets          map[string][]string `json:"sets"` // set name -> list of addresses
	store         *Store
}

func (cache *SetCache) cachePayloadSchemaVersion() int {
	return cache.SchemaVersion
}

func (cache *SetCache) setCachePayloadSchemaVersion(version int) {
	cache.SchemaVersion = version
}

func (cache *SetCache) supportedCachePayloadSchemaVersion() int {
	return cachePayloadSchemaVersion
}

// LoadSetCacheFromStore loads the set cache from the provided store.
func LoadSetCacheFromStore(store *Store) SetCache {
	cache := SetCache{SchemaVersion: cachePayloadSchemaVersion, Sets: make(map[string][]string)}
	cache.bindStore(store)
	if err := loadSignedCacheWithKey(store, store.path("set_cache.json"), &cache); err != nil {
		warnCacheLoadError("set cache", err)
	}
	return cache
}

// SaveCache saves the set cache to disk with HMAC signature
func (cache *SetCache) SaveCache() error {
	return saveSignedCacheWithKey(cache.store, storePath(cache.store, "set_cache.json"), cache)
}

// SaveCacheLocked saves the set cache while the caller already holds the
// APCLIENT_DATA mutation lock.
func (cache *SetCache) SaveCacheLocked() error {
	return saveSignedCacheWithoutClientLock(cache.store, storePath(cache.store, "set_cache.json"), cache)
}

// CreateOrUpdateSet creates or updates a set with the given addresses
// Addresses are resolved from aliases before being stored
func (cache *SetCache) CreateOrUpdateSet(setName string, addresses []string, aliasCache *AliasCache) error {
	setName = refname.NormalizeSet(setName)
	if err := refname.ValidateSet(setName); err != nil {
		return err
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

	cache.Sets[setName] = resolvedAddresses

	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save set cache: %w", err)
	}

	return nil
}

// AddToSet adds addresses to an existing set (or creates it if it doesn't exist)
func (cache *SetCache) AddToSet(setName string, addresses []string, aliasCache *AliasCache) error {
	setName = refname.NormalizeSet(setName)
	if err := refname.ValidateSet(setName); err != nil {
		return err
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
	for _, addr := range resolvedAddresses {
		found := false
		for _, existingAddr := range existing {
			if existingAddr == addr {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, addr)
		}
	}

	cache.Sets[setName] = existing

	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save set cache: %w", err)
	}
	return nil
}

// RemoveFromSet removes addresses from a set
func (cache *SetCache) RemoveFromSet(setName string, addresses []string, aliasCache *AliasCache) error {
	setName = refname.NormalizeSet(setName)
	if err := refname.ValidateSet(setName); err != nil {
		return err
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
	filtered := make([]string, 0, len(existing))
	for _, addr := range existing {
		if !toRemove[addr] {
			filtered = append(filtered, addr)
		}
	}

	if len(filtered) == 0 {
		delete(cache.Sets, setName)
	} else {
		cache.Sets[setName] = filtered
	}

	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save set cache: %w", err)
	}

	return nil
}

// DeleteSet deletes a set
func (cache *SetCache) DeleteSet(setName string) error {
	setName = refname.NormalizeSet(setName)
	if err := refname.ValidateSet(setName); err != nil {
		return err
	}
	if _, exists := cache.Sets[setName]; !exists {
		return fmt.Errorf("set '%s' does not exist", setName)
	}

	delete(cache.Sets, setName)

	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save set cache: %w", err)
	}

	return nil
}

// GetSet returns the addresses in a set
func (cache *SetCache) GetSet(setName string) ([]string, error) {
	setName = refname.NormalizeSet(setName)
	addresses, exists := cache.Sets[setName]
	if !exists {
		return nil, fmt.Errorf("set '%s' does not exist", setName)
	}
	return addresses, nil
}

// ResolveAddressOrSet resolves either a single address/alias or a set name to a list of addresses
// If input starts with '@', it's treated as a set name
// Otherwise, it's treated as a single address/alias
func (cache *SetCache) ResolveAddressOrSet(input string, aliasCache *AliasCache) ([]string, error) {
	if len(input) > 0 && input[0] == '@' {
		// It's a set reference
		setName := refname.NormalizeSet(input[1:])
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
