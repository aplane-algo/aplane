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
	if err := loadSignedCacheWithKey(store, store.path("alias_cache.json"), &cache); err != nil {
		warnCacheLoadError("alias cache", err)
	}
	return cache
}

// SaveCacheLocked saves the alias cache while the caller already holds the
// APCLIENT_DATA mutation lock.
func (cache *AliasCache) SaveCacheLocked() error {
	return saveSignedCacheWithoutClientLock(cache.store, cache.store.path("alias_cache.json"), cache)
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
