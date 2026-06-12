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

// BuildAuthCacheFromStore builds the auth cache using the provided store.
func BuildAuthCacheFromStore(store *Store, algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	return BuildAuthCacheFromStoreWithContext(context.Background(), store, algodClient, aliasCache, signerCache, network)
}

func BuildAuthCacheFromStoreWithContext(ctx context.Context, store *Store, algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	return buildAuthCacheFromStore(ctx, store, algodClient, aliasCache, signerCache, network)
}

func buildAuthCacheFromStore(ctx context.Context, store *Store, algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	// Load existing cache from disk
	cache := LoadAuthCacheFromStore(store, network)

	if algodClient == nil {
		return cache
	}

	// Build superset of addresses to check: aliases + signer accounts
	addressesToCheck := make(map[string]bool)

	// Add all aliases
	for _, addr := range aliasCache.Aliases {
		addressesToCheck[addr] = true
	}

	// Add all signer accounts (if connected)
	if signerCache != nil {
		for addr := range signerCache.Keys {
			addressesToCheck[addr] = true
		}
	}

	if len(addressesToCheck) == 0 {
		cache.ensureInitialized()
		cache.AuthAddresses = make(map[string]string)
		_ = cache.SaveCache(network)
		return cache
	}

	Debug("building auth address cache", "network", network, "addresses", len(addressesToCheck))
	updates := make(map[string]string, len(addressesToCheck))
	for address := range addressesToCheck {
		acctInfo, err := algodClient.AccountInformation(address).Do(ctx)
		if err != nil {
			// If account doesn't exist or query fails, skip it
			continue
		}

		authAddr := acctInfo.AuthAddr
		if authAddr == "" || authAddr == address {
			// Not rekeyed, store empty string
			updates[address] = ""
		} else {
			// Rekeyed, store auth address
			updates[address] = authAddr
		}
	}

	cache.ensureInitialized()
	for address, authAddr := range updates {
		cache.AuthAddresses[address] = authAddr
	}
	for address := range cache.AuthAddresses {
		if !addressesToCheck[address] {
			delete(cache.AuthAddresses, address)
		}
	}

	// Save to disk
	if saveErr := cache.SaveCache(network); saveErr != nil {
		warnf("failed to save auth cache: %v", saveErr)
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
	cache.ensureInitialized()

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
