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

// GetSet returns the addresses in a set
func (cache *SetCache) GetSet(setName string) ([]string, error) {
	setName = refname.NormalizeSet(setName)
	addresses, exists := cache.Sets[setName]
	if !exists {
		return nil, fmt.Errorf("set '%s' does not exist", setName)
	}
	return addresses, nil
}
