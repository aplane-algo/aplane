// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"context"
	"fmt"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

var authCacheMutexInitMu sync.Mutex

// GetAuthCacheFilename returns the auth cache filename for a network
func GetAuthCacheFilename(network string) string {
	return GetAuthCacheFilenameForStore(nil, network)
}

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
		mu:            &sync.RWMutex{},
	}
	cache.bindStore(store)
	return cache
}

// LoadAuthCache loads the auth address cache from disk for the specified network
func LoadAuthCache(network string) AuthAddressCache {
	return LoadAuthCacheFromStore(nil, network)
}

// LoadAuthCacheFromStore loads the auth address cache from the provided store.
func LoadAuthCacheFromStore(store *Store, network string) AuthAddressCache {
	cache := NewAuthAddressCacheForStore(store)
	if err := loadSignedCacheWithKey(store, GetAuthCacheFilenameForStore(store, network), &cache); err != nil {
		warnCacheLoadError("auth cache", err)
	}
	return cache
}

// SaveCache saves the auth address cache to disk for the specified network
func (cache *AuthAddressCache) SaveCache(network string) error {
	cache.ensureMutex()
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return cache.saveCacheUnlocked(network)
}

// SaveCacheLocked saves the auth cache while the caller already holds the
// APCLIENT_DATA mutation lock.
func (cache *AuthAddressCache) SaveCacheLocked(network string) error {
	cache.ensureMutex()
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return cache.saveCacheUnlocked(network)
}

// BuildAuthCache builds the auth address cache by querying the blockchain for all alias and signer addresses
// It loads existing cache from disk, updates it with current blockchain data, and saves back to disk
func BuildAuthCache(algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	return BuildAuthCacheWithContext(context.Background(), algodClient, aliasCache, signerCache, network)
}

func BuildAuthCacheWithContext(ctx context.Context, algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	return BuildAuthCacheFromStoreWithContext(ctx, nil, algodClient, aliasCache, signerCache, network)
}

// BuildAuthCacheFromStore builds the auth cache using the provided store.
func BuildAuthCacheFromStore(store *Store, algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	return BuildAuthCacheFromStoreWithContext(context.Background(), store, algodClient, aliasCache, signerCache, network)
}

func BuildAuthCacheFromStoreWithContext(ctx context.Context, store *Store, algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	return buildAuthCacheFromStore(ctx, store, algodClient, aliasCache, signerCache, network, false)
}

func BuildAuthCacheFromStoreLockedWithContext(ctx context.Context, store *Store, algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	return buildAuthCacheFromStore(ctx, store, algodClient, aliasCache, signerCache, network, true)
}

func buildAuthCacheFromStore(ctx context.Context, store *Store, algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string, locked bool) AuthAddressCache {
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
		cache.ensureMutex()
		cache.mu.Lock()
		cache.AuthAddresses = make(map[string]string)
		cache.mu.Unlock()
		if locked {
			_ = cache.SaveCacheLocked(network)
		} else {
			_ = cache.SaveCache(network)
		}
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

	cache.ensureMutex()
	cache.mu.Lock()
	for address, authAddr := range updates {
		cache.AuthAddresses[address] = authAddr
	}
	for address := range cache.AuthAddresses {
		if !addressesToCheck[address] {
			delete(cache.AuthAddresses, address)
		}
	}
	cache.mu.Unlock()

	// Save to disk
	saveErr := error(nil)
	if locked {
		saveErr = cache.SaveCacheLocked(network)
	} else {
		saveErr = cache.SaveCache(network)
	}
	if saveErr != nil {
		warnf("failed to save auth cache: %v", saveErr)
	}

	return cache
}

// UpdateAuthAddress updates the cached auth address for an account
// If authAddress is empty or same as address, it means the account is not rekeyed
func (cache *AuthAddressCache) UpdateAuthAddress(address string, authAddress string, network string) error {
	cache.ensureMutex()
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Store normalized: if auth address is same as address, store empty string
	if authAddress == address {
		cache.AuthAddresses[address] = ""
	} else {
		cache.AuthAddresses[address] = authAddress
	}

	// Save to disk
	return cache.saveCacheUnlocked(network)
}

// GetAuthAddress returns the cached auth address for an account
// Returns empty string if not cached or if account is not rekeyed
func (cache *AuthAddressCache) GetAuthAddress(address string) (string, bool) {
	cache.ensureMutex()
	cache.mu.RLock()
	defer cache.mu.RUnlock()

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

	cache.ensureMutex()
	cache.mu.Lock()
	defer cache.mu.Unlock()

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
	if err := cache.saveCacheUnlocked(network); err != nil {
		return authAddr, fmt.Errorf("updated cache but failed to save: %w", err)
	}

	return authAddr, nil
}

// PruneToOwnedAddresses removes auth-cache entries for addresses no longer owned
// by aliases or signer inventory and persists the updated cache.
func (cache *AuthAddressCache) PruneToOwnedAddresses(owned map[string]bool, network string) error {
	cache.ensureMutex()
	cache.mu.Lock()
	defer cache.mu.Unlock()

	for address := range cache.AuthAddresses {
		if !owned[address] {
			delete(cache.AuthAddresses, address)
		}
	}

	return cache.saveCacheUnlocked(network)
}

// UpdateAuthAddressLocked updates the cached auth address while the caller
// already holds the APCLIENT_DATA mutation lock.
func (cache *AuthAddressCache) UpdateAuthAddressLocked(address string, authAddress string, network string) error {
	cache.ensureMutex()
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if authAddress == address {
		cache.AuthAddresses[address] = ""
	} else {
		cache.AuthAddresses[address] = authAddress
	}

	return cache.saveCacheUnlocked(network)
}

// RefreshAuthAddressLocked refreshes one address from algod while the caller
// already holds the APCLIENT_DATA mutation lock.
func (cache *AuthAddressCache) RefreshAuthAddressLocked(algodClient *algod.Client, address string, network string) (string, error) {
	return cache.RefreshAuthAddressLockedWithContext(context.Background(), algodClient, address, network)
}

func (cache *AuthAddressCache) RefreshAuthAddressLockedWithContext(ctx context.Context, algodClient *algod.Client, address string, network string) (string, error) {
	acctInfo, err := algodClient.AccountInformation(address).Do(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to query account info: %w", err)
	}

	cache.ensureMutex()
	cache.mu.Lock()
	defer cache.mu.Unlock()

	authAddr := acctInfo.AuthAddr
	if authAddr == "" || authAddr == address {
		cache.AuthAddresses[address] = ""
		authAddr = ""
	} else {
		cache.AuthAddresses[address] = authAddr
	}

	if err := cache.saveCacheUnlocked(network); err != nil {
		return authAddr, fmt.Errorf("updated cache but failed to save: %w", err)
	}

	return authAddr, nil
}

// PruneToOwnedAddressesLocked removes stale auth-cache entries while the caller
// already holds the APCLIENT_DATA mutation lock.
func (cache *AuthAddressCache) PruneToOwnedAddressesLocked(owned map[string]bool, network string) error {
	cache.ensureMutex()
	cache.mu.Lock()
	defer cache.mu.Unlock()

	for address := range cache.AuthAddresses {
		if !owned[address] {
			delete(cache.AuthAddresses, address)
		}
	}

	return cache.saveCacheUnlocked(network)
}

func (cache *AuthAddressCache) ensureMutex() {
	authCacheMutexInitMu.Lock()
	defer authCacheMutexInitMu.Unlock()
	if cache.mu == nil {
		cache.mu = &sync.RWMutex{}
	}
	if cache.AuthAddresses == nil {
		cache.AuthAddresses = make(map[string]string)
	}
}

func (cache *AuthAddressCache) saveCacheUnlocked(network string) error {
	return saveSignedCacheWithoutClientLock(cache.store, GetAuthCacheFilenameForStore(cache.store, network), cache)
}
