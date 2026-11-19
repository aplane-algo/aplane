// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// GetAuthCacheFilenameForStore returns the auth cache filename for a network in the provided store.
func GetAuthCacheFilenameForStore(store *Store, network string) string {
	return storePath(store, fmt.Sprintf("%s_auth_cache.json", network))
}

// NewAuthAddressCache creates a new empty auth address cache
func NewAuthAddressCache() AuthAddressCache {
	return NewAuthAddressCacheForStore(nil)
}

// NewAuthAddressCacheForStore creates a new empty auth address cache bound to a store.
func NewAuthAddressCacheForStore(store *Store) AuthAddressCache {
	cache := AuthAddressCache{
		SchemaVersion: cachePayloadSchemaVersion,
		AuthAddresses: make(map[string]string),
	}
	cache.bindStore(store)
	return cache
}

// LoadAuthCacheFromStore loads the auth address cache from the provided store.
func LoadAuthCacheFromStore(store *Store, network string) AuthAddressCache {
	cache := NewAuthAddressCacheForStore(store)
	if err := loadSignedCacheWithKey(store, GetAuthCacheFilenameForStore(store, network), &cache); err != nil {
		warnCacheLoadError("auth cache", err)
	}
	return cache
}

// SaveCache saves the auth address cache to disk for the specified network.
//
// Auth-cache persistence never takes the APCLIENT_DATA mutation lock itself
// (it writes through saveSignedCacheWithoutClientLock); callers needing
// mutation atomicity hold the clientdata lock at a higher level. The former
// *Locked method variants were byte-identical and were collapsed away.
func (cache *AuthAddressCache) SaveCache(network string) error {
	cache.ensureInitialized()
	return cache.persistCache(network)
}

// QueryAuthAddresses asks algod, with ctx, for the auth address of each of
// addresses. An account that signs for itself answers ""; an address whose
// query fails, or every address when algodClient is nil, is left out. It
// takes no lock: a caller queries first and then merges the answers under
// the client-data lock (MergeAuthCacheIntoStore), so the queries never hold
// that lock.
func QueryAuthAddresses(ctx context.Context, algodClient *algod.Client, addresses map[string]bool) map[string]string {
	answers := make(map[string]string, len(addresses))
	if algodClient == nil {
		return answers
	}
	Debug("querying auth addresses", "addresses", len(addresses))
	for address := range addresses {
		acctInfo, err := algodClient.AccountInformation(address).Do(ctx)
		if err != nil {
			continue
		}
		if authAddr := acctInfo.AuthAddr; authAddr != "" && authAddr != address {
			answers[address] = authAddr
		} else {
			answers[address] = ""
		}
	}
	return answers
}

// MergeAuthCacheIntoStore reloads the network's auth-address cache from
// store, sets the entries answers gives, removes the entry of every address
// not in owned, the client's known accounts, and saves the result. An owned
// address with no answer keeps the entry it has on disk, which may be
// another process's. The caller holds the client-data lock, so no other
// process writes the file between the load and the save.
func MergeAuthCacheIntoStore(store *Store, network string, answers map[string]string, owned map[string]bool) AuthAddressCache {
	cache := LoadAuthCacheFromStore(store, network)
	cache.ensureInitialized()
	for address, authAddr := range answers {
		cache.AuthAddresses[address] = authAddr
	}
	for address := range cache.AuthAddresses {
		if !owned[address] {
			delete(cache.AuthAddresses, address)
		}
	}
	if err := cache.SaveCache(network); err != nil {
		warnf("failed to save auth cache: %v", err)
	}
	return cache
}

// UpdateAuthAddress updates the cached auth address for an account
// If authAddress is empty or same as address, it means the account is not rekeyed
func (cache *AuthAddressCache) UpdateAuthAddress(address string, authAddress string, network string) error {
	cache.ensureInitialized()

	// Store normalized: if auth address is same as address, store empty string
	if authAddress == address {
		cache.AuthAddresses[address] = ""
	} else {
		cache.AuthAddresses[address] = authAddress
	}

	// Save to disk
	return cache.persistCache(network)
}

// GetAuthAddress returns the cached auth address for an account
// Returns empty string if not cached or if account is not rekeyed
func (cache *AuthAddressCache) GetAuthAddress(address string) (string, bool) {
	if cache == nil || cache.AuthAddresses == nil {
		return "", false
	}

	authAddr, exists := cache.AuthAddresses[address]
	return authAddr, exists
}

// ResolveEffectiveSigner returns the effective signer address for a given account.
// If the account is rekeyed, returns the auth address. Otherwise returns the original address.
// Safe to call on nil receiver.
func (cache *AuthAddressCache) ResolveEffectiveSigner(sender string) string {
	if cache == nil {
		return sender
	}
	if authAddr, exists := cache.GetAuthAddress(sender); exists && authAddr != "" {
		return authAddr
	}
	return sender
}

// RefreshAuthAddress queries the blockchain for the current auth address and updates cache
func (cache *AuthAddressCache) RefreshAuthAddress(algodClient *algod.Client, address string, network string) (string, error) {
	return cache.RefreshAuthAddressWithContext(context.Background(), algodClient, address, network)
}

func (cache *AuthAddressCache) RefreshAuthAddressWithContext(ctx context.Context, algodClient *algod.Client, address string, network string) (string, error) {
	acctInfo, err := algodClient.AccountInformation(address).Do(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to query account info: %w", err)
	}

	cache.ensureInitialized()

	authAddr := acctInfo.AuthAddr
	if authAddr == "" || authAddr == address {
		// Not rekeyed, store empty string
		cache.AuthAddresses[address] = ""
		authAddr = ""
	} else {
		// Rekeyed, store auth address
		cache.AuthAddresses[address] = authAddr
	}

	// Save to disk
	if err := cache.persistCache(network); err != nil {
		return authAddr, fmt.Errorf("updated cache but failed to save: %w", err)
	}

	return authAddr, nil
}

// PruneToOwnedAddresses removes auth-cache entries for addresses no longer owned
// by aliases or signer inventory and persists the updated cache.
func (cache *AuthAddressCache) PruneToOwnedAddresses(owned map[string]bool, network string) error {
	cache.ensureInitialized()

	for address := range cache.AuthAddresses {
		if !owned[address] {
			delete(cache.AuthAddresses, address)
		}
	}

	return cache.persistCache(network)
}

// ensureInitialized makes a zero-value AuthAddressCache usable by
// initializing its backing map.
func (cache *AuthAddressCache) ensureInitialized() {
	if cache.AuthAddresses == nil {
		cache.AuthAddresses = make(map[string]string)
	}
}

func (cache *AuthAddressCache) persistCache(network string) error {
	return saveSignedCacheWithoutClientLock(cache.store, GetAuthCacheFilenameForStore(cache.store, network), cache)
}
