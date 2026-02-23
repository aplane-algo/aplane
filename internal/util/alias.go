// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"sort"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// LoadAliasCache loads the alias cache from disk with HMAC verification
func LoadAliasCache() AliasCache {
	cache := AliasCache{Aliases: make(map[string]string)}
	if err := loadSignedCacheWithKey(getCachePath("alias_cache.json"), &cache); err != nil {
		fmt.Printf("Warning: Failed to load alias cache: %v\n", err)
	}
	return cache
}

// SaveCache saves the alias cache to disk with HMAC signature
func (cache *AliasCache) SaveCache() error {
	return saveSignedCacheWithKey(getCachePath("alias_cache.json"), cache)
}

// UpdateAlias adds or updates an alias
func (cache *AliasCache) UpdateAlias(alias, address string, force bool) error {
	decoded, err := types.DecodeAddress(address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	address = decoded.String() // Normalize to uppercase

	if existingAddr, exists := cache.Aliases[alias]; exists {
		if existingAddr == address {
			fmt.Printf("Alias '%s' already points to %s\n", alias, cache.FormatAddress(address, nil, nil, ""))
			return nil
		}
		if !force {
			return fmt.Errorf("alias '%s' already exists and points to %s. Use 'alias update' to change it", alias, cache.FormatAddress(existingAddr, nil, nil, ""))
		}
		fmt.Printf("Updating alias: %s -> %s (was %s)\n", alias, cache.FormatAddress(address, nil, nil, ""), cache.FormatAddress(existingAddr, nil, nil, ""))
	} else {
		fmt.Printf("Adding new alias: %s -> %s\n", alias, cache.FormatAddress(address, nil, nil, ""))
	}

	cache.Aliases[alias] = address
	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save alias cache: %w", err)
	}

	return nil
}

// RemoveAlias removes an alias
func (cache *AliasCache) RemoveAlias(alias string) error {
	if _, exists := cache.Aliases[alias]; !exists {
		return fmt.Errorf("alias '%s' does not exist", alias)
	}

	delete(cache.Aliases, alias)
	if err := cache.SaveCache(); err != nil {
		return fmt.Errorf("failed to save alias cache: %w", err)
	}

	fmt.Printf("Removed alias: %s\n", alias)
	return nil
}

// ResolveAddress resolves an alias or address to an address (normalized to uppercase)
func (cache *AliasCache) ResolveAddress(input string) (string, error) {
	// Check alias first - user-defined names take precedence
	if address, exists := cache.Aliases[input]; exists {
		return address, nil
	}

	// Not an alias, try to decode as Algorand address (uppercase before decode, normalize output)
	if decoded, err := types.DecodeAddress(strings.ToUpper(input)); err == nil {
		return decoded.String(), nil
	}

	return "", fmt.Errorf("'%s' is neither a valid Algorand address nor a known alias", input)
}

// HasAlias returns true if the given name is a registered alias
func (cache *AliasCache) HasAlias(name string) bool {
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

// FormatAlias formats an alias name with cyan/teal color if terminal supports it
func (cache *AliasCache) FormatAlias(alias string) string {
	if supportsColor() {
		return fmt.Sprintf("\033[36m%s\033[0m", alias)
	}
	return alias
}

// FormatAddress formats an address with optional alias display
// Format: "FULL_ADDRESS (alias_name)" or "FULL_ADDRESS"
// - alias is shown if one exists
// Color indicates signature capability:
// - Yellow: signable falcon (falcon1024 key can sign remotely)
// - Cyan: signable ed25519 (ed25519 key can sign remotely)
// - No color: cannot sign remotely
// signerCache: optional SignerCache to check if address can be signed remotely (if nil, signer check is skipped)
// authCache: optional AuthAddressCache to check rekey status (if nil, rekey check is skipped)
// authAddress: optional explicit auth address for rekeyed accounts (overrides authCache lookup)
func (cache *AliasCache) FormatAddress(address string, signerCache *SignerCache, authCache *AuthAddressCache, authAddress string) string {
	// Determine the effective signing address (auth address if rekeyed)
	effectiveSigningAddress := address

	if authAddress != "" && authAddress != address {
		effectiveSigningAddress = authAddress
	} else if authCache != nil {
		// Check AuthCache for rekey status
		if cachedAuthAddr, exists := authCache.GetAuthAddress(address); exists && cachedAuthAddr != "" {
			effectiveSigningAddress = cachedAuthAddr
		}
	}

	// Build formatted string with alias (no key type label)
	var formatted string
	alias := cache.GetAliasForAddress(address)

	if alias != "" {
		// Has alias: "ADDRESS (alias)"
		formatted = fmt.Sprintf("%s (%s)", address, alias)
	} else {
		// No alias: "ADDRESS"
		formatted = address
	}

	// Color based on whether the account is signable (considering rekey status)
	if IsAccountSignable(address, signerCache, authCache) {
		// Get the key type from the effective signing address to determine color
		keyType := signerCache.GetKeyType(effectiveSigningAddress)

		// Format with color using the signerCache's color formatter
		if signerCache != nil && signerCache.colorFormatter != nil {
			return FormatAddressWithColor(formatted, keyType, signerCache.colorFormatter)
		}

		// Fallback for when color not supported
		if !supportsColor() {
			return formatted + " @" // @ symbol for remote signer when color not supported
		}
		return formatted
	}

	// No special formatting for regular addresses
	return formatted
}

// ListAliases lists all aliases
func (cache *AliasCache) ListAliases(signerCache *SignerCache, authCache *AuthAddressCache) {
	if len(cache.Aliases) == 0 {
		fmt.Println("No aliases defined")
		return
	}

	// Extract and sort alias names alphabetically
	aliases := make([]string, 0, len(cache.Aliases))
	for alias := range cache.Aliases {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	fmt.Println("Defined aliases:")
	for _, alias := range aliases {
		address := cache.Aliases[alias]
		fmt.Printf("  %s\n", cache.FormatAddress(address, signerCache, authCache, ""))
	}

	if signerCache != nil && signerCache.Count() > 0 {
		fmt.Println("\nColor legend:")
		fmt.Println("  Yellow = signable falcon")
		fmt.Println("  Cyan = signable ed25519")
	}
}
