// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// GetAuthCacheFilename returns the auth cache filename for a network
func GetAuthCacheFilename(network string) string {
	return getCachePath(fmt.Sprintf("%s_auth_cache.json", network))
}

// NewAuthAddressCache creates a new empty auth address cache
func NewAuthAddressCache() AuthAddressCache {
	return AuthAddressCache{AuthAddresses: make(map[string]string)}
}

// LoadAuthCache loads the auth address cache from disk for the specified network
func LoadAuthCache(network string) AuthAddressCache {
	cache := NewAuthAddressCache()
	if err := loadSignedCacheWithKey(GetAuthCacheFilename(network), &cache); err != nil {
		fmt.Printf("Warning: Failed to load auth cache for %s: %v\n", network, err)
	}
	return cache
}

// SaveCache saves the auth address cache to disk for the specified network
func (cache *AuthAddressCache) SaveCache(network string) error {
	return saveSignedCacheWithKey(GetAuthCacheFilename(network), cache)
}

// BuildAuthCache builds the auth address cache by querying the blockchain for all alias and signer addresses
// It loads existing cache from disk, updates it with current blockchain data, and saves back to disk
func BuildAuthCache(algodClient *algod.Client, aliasCache *AliasCache, signerCache *SignerCache, network string) AuthAddressCache {
	// Load existing cache from disk
	cache := LoadAuthCache(network)

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
		return cache
	}

	Debug("building auth address cache", "network", network, "addresses", len(addressesToCheck))
	for address := range addressesToCheck {
		acctInfo, err := algodClient.AccountInformation(address).Do(context.Background())
		if err != nil {
			// If account doesn't exist or query fails, skip it
			continue
		}

		authAddr := acctInfo.AuthAddr
		if authAddr == "" || authAddr == address {
			// Not rekeyed, store empty string
			cache.AuthAddresses[address] = ""
		} else {
			// Rekeyed, store auth address
			cache.AuthAddresses[address] = authAddr
		}
	}

	// Save to disk
	if err := cache.SaveCache(network); err != nil {
		fmt.Printf("Warning: failed to save auth cache: %v\n", err)
	}

	return cache
}

// UpdateAuthAddress updates the cached auth address for an account
// If authAddress is empty or same as address, it means the account is not rekeyed
func (cache *AuthAddressCache) UpdateAuthAddress(address string, authAddress string, network string) error {
	// Store normalized: if auth address is same as address, store empty string
	if authAddress == address {
		cache.AuthAddresses[address] = ""
	} else {
		cache.AuthAddresses[address] = authAddress
	}

	// Save to disk
	return cache.SaveCache(network)
}

// GetAuthAddress returns the cached auth address for an account
// Returns empty string if not cached or if account is not rekeyed
func (cache *AuthAddressCache) GetAuthAddress(address string) (string, bool) {
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
	acctInfo, err := algodClient.AccountInformation(address).Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to query account info: %w", err)
	}

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
	if err := cache.SaveCache(network); err != nil {
		return authAddr, fmt.Errorf("updated cache but failed to save: %w", err)
	}

	return authAddr, nil
}
