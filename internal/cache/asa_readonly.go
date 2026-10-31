// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"errors"
	"fmt"
	"os"
)

// ErrCacheKeyMissing reports a cache file whose integrity key is absent, so
// the file cannot be verified.
var ErrCacheKeyMissing = errors.New("cache file exists but its integrity key is missing")

// LoadASACacheReadOnly loads a network's ASA cache from store without writing
// anything. Unlike LoadASACacheFromStore it never creates the cache
// directory or the .cache_key file, and the returned cache is not bound to the
// store, so it cannot be saved back.
//
// The built-in entries are always present. A missing store, cache directory,
// key or cache file is an empty cache, not an error. A cache file that cannot
// be read or verified is returned as an error (ErrCacheTampered for a failed
// integrity check, ErrCacheKeyMissing for a file with no key), together with
// the built-in entries, so the caller can report it rather than mistake it for
// an empty cache.
func LoadASACacheReadOnly(store *Store, network string) (ASACache, error) {
	cache := builtinASACache(network)
	if !store.persistent() {
		return cache, nil
	}
	cacheFile := GetASACacheFilenameForStore(store, network)
	key, err := readCacheKeyFile(storePath(store, ".cache_key"))
	if err != nil {
		if !os.IsNotExist(err) {
			return cache, err
		}
		if _, statErr := os.Stat(cacheFile); statErr == nil {
			return cache, fmt.Errorf("%s: %w", cacheFile, ErrCacheKeyMissing)
		} else if !os.IsNotExist(statErr) {
			return cache, fmt.Errorf("failed to read cache file: %w", statErr)
		}
		return cache, nil
	}
	filecache := ASACache{SchemaVersion: cachePayloadSchemaVersion, Assets: make(map[uint64]ASAInfo)}
	if err := LoadSignedCache(cacheFile, key, &filecache); err != nil {
		return cache, err
	}
	for id, info := range filecache.Assets {
		cache.Assets[id] = PreferBuiltin(network, id, info)
	}
	return cache, nil
}
