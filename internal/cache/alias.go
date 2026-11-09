// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/refname"
)

// LoadAliasCacheFromStore loads the alias cache from the provided store.
func LoadAliasCacheFromStore(store *Store) AliasCache {
	cache := AliasCache{SchemaVersion: cachePayloadSchemaVersion, Aliases: make(map[string]string)}
	cache.bindStore(store)
	if err := loadSignedCacheWithKey(store, storePath(store, "alias_cache.json"), &cache); err != nil {
		warnCacheLoadError("alias cache", err)
	}
	cache.dropAddressNamedAliases()
	return cache
}

// dropAddressNamedAliases ignores any alias whose name is itself an address.
// Creating one is refused, so one in the cache was written by an older
// version or planted to redirect that address; it could never resolve, since
// an address always resolves as itself, and listing it would show one address
// labelled as another. The next save drops it from the file.
func (cache *AliasCache) dropAddressNamedAliases() {
	for name, address := range cache.Aliases {
		if refname.IsAddress(name) {
			warnf("alias cache: ignoring alias %q, which points to %s: its name is an Algorand address, so it would redirect that address", name, address)
			delete(cache.Aliases, name)
		}
	}
}

// SaveCache saves the alias cache to disk with HMAC signature
func (cache *AliasCache) SaveCache() error {
	return saveSignedCacheWithKey(cache.store, storePath(cache.store, "alias_cache.json"), cache)
}

// SaveCacheLocked saves the alias cache while the caller already holds the
// APCLIENT_DATA mutation lock.
func (cache *AliasCache) SaveCacheLocked() error {
	return saveSignedCacheWithoutClientLock(cache.store, storePath(cache.store, "alias_cache.json"), cache)
}

// UpdateAlias adds or updates an alias. The caller is responsible for any
// user-facing message about the change; this function only mutates state.
func (cache *AliasCache) UpdateAlias(alias, address string, force bool) error {
	alias = refname.NormalizeAlias(alias)
	if err := refname.ValidateAlias(alias); err != nil {
		return err
	}
	decoded, err := types.DecodeAddress(address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	address = decoded.String() // Normalize to uppercase

	if existingAddr, exists := cache.Aliases[alias]; exists {
		if existingAddr == address {
			return nil
		}
		if !force {
			return fmt.Errorf("alias '%s' already exists and points to %s. Use 'alias update' to change it", alias, existingAddr)
		}
	}

	cache.Aliases[alias] = address
	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save alias cache: %w", err)
	}

	return nil
}

// RemoveAlias removes an alias. The caller is responsible for any user-facing
// confirmation message; this function only mutates state.
func (cache *AliasCache) RemoveAlias(alias string) error {
	alias = refname.NormalizeAlias(alias)
	if err := refname.ValidateAlias(alias); err != nil {
		return err
	}
	if _, exists := cache.Aliases[alias]; !exists {
		return fmt.Errorf("alias '%s' does not exist", alias)
	}

	delete(cache.Aliases, alias)
	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save alias cache: %w", err)
	}

	return nil
}

// ResolveAddress resolves an address or alias to an address (normalized to
// uppercase). An address always resolves as itself, in either case, before
// any alias is consulted, so no alias can redirect it.
func (cache *AliasCache) ResolveAddress(input string) (string, error) {
	if decoded, err := types.DecodeAddress(strings.ToUpper(input)); err == nil {
		return decoded.String(), nil
	}
	if address, exists := cache.Aliases[refname.NormalizeAlias(input)]; exists {
		return address, nil
	}
	return "", fmt.Errorf("'%s' is neither a valid Algorand address nor a known alias", input)
}

// HasAlias returns true if the given name is a registered alias
func (cache *AliasCache) HasAlias(name string) bool {
	name = refname.NormalizeAlias(name)
	_, exists := cache.Aliases[name]
	return exists
}

// GetAliasForAddress performs reverse lookup to find the alias for an address
func (cache *AliasCache) GetAliasForAddress(address string) string {
	for alias, addr := range cache.Aliases {
		if addr == address {
			return alias
		}
	}
	return ""
}
