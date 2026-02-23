// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"strings"
)

// NewSignerCache creates an empty SignerCache
func NewSignerCache() SignerCache {
	return SignerCache{
		Keys:           make(map[string]string),
		GenericLsigs:   make(map[string]bool),
		LsigSizes:      make(map[string]int),
		RuntimeArgs:    make(map[string][]RuntimeArgInfo),
		colorFormatter: nil, // Can be set later by caller
	}
}

// SetColorFormatter sets the color formatter function for this cache
func (cache *SignerCache) SetColorFormatter(formatter ColorFormatter) {
	cache.colorFormatter = formatter
}

// HasAddress checks if Signer can sign for this address
func (cache *SignerCache) HasAddress(address string) bool {
	_, exists := cache.Keys[address]
	return exists
}

// GetKeyType returns the key type for an address ("falcon1024-v1" or "ed25519")
// Returns empty string if address is not in cache
func (cache *SignerCache) GetKeyType(address string) string {
	return cache.Keys[address]
}

// AddAddress adds an address to the signer cache with its key type
func (cache *SignerCache) AddAddress(address string, keyType string) {
	cache.Keys[address] = keyType
}

// RemoveAddress removes an address from the signer cache
func (cache *SignerCache) RemoveAddress(address string) {
	delete(cache.Keys, address)
}

// Count returns the number of addresses in the cache
func (cache *SignerCache) Count() int {
	return len(cache.Keys)
}

// IsGenericLsig checks if an address is a generic LogicSig (no cryptographic signature needed)
func (cache *SignerCache) IsGenericLsig(address string) bool {
	if cache.GenericLsigs == nil {
		return false
	}
	return cache.GenericLsigs[address]
}

// SetGenericLsig marks an address as a generic LogicSig
func (cache *SignerCache) SetGenericLsig(address string, isGeneric bool) {
	if cache.GenericLsigs == nil {
		cache.GenericLsigs = make(map[string]bool)
	}
	if isGeneric {
		cache.GenericLsigs[address] = true
	} else {
		delete(cache.GenericLsigs, address)
	}
}

// GetLsigSize returns the total LogicSig size for an address (0 if not LSig)
// This includes bytecode + crypto signature size for DSA-based LSigs.
func (cache *SignerCache) GetLsigSize(address string) int {
	if cache.LsigSizes == nil {
		return 0
	}
	return cache.LsigSizes[address]
}

// SetLsigSize sets the total LogicSig size for an address
func (cache *SignerCache) SetLsigSize(address string, size int) {
	if cache.LsigSizes == nil {
		cache.LsigSizes = make(map[string]int)
	}
	cache.LsigSizes[address] = size
}

// GetRuntimeArgs returns the runtime args schema for a generic lsig address
// Returns nil if address is not in cache or has no runtime args
func (cache *SignerCache) GetRuntimeArgs(address string) []RuntimeArgInfo {
	if cache.RuntimeArgs == nil {
		return nil
	}
	return cache.RuntimeArgs[address]
}

// SetRuntimeArgs sets the runtime args schema for a generic lsig address
func (cache *SignerCache) SetRuntimeArgs(address string, args []RuntimeArgInfo) {
	if cache.RuntimeArgs == nil {
		cache.RuntimeArgs = make(map[string][]RuntimeArgInfo)
	}
	if len(args) > 0 {
		cache.RuntimeArgs[address] = args
	} else {
		delete(cache.RuntimeArgs, address)
	}
}

// ValidateLsigArgs validates that provided lsig args match the schema for a generic lsig address.
// Returns nil if valid, or an error describing what's wrong.
// Checks:
//   - All required args are provided
//   - All provided arg names are valid (exist in schema)
func (cache *SignerCache) ValidateLsigArgs(address string, providedArgs map[string][]byte) error {
	schema := cache.GetRuntimeArgs(address)
	if schema == nil {
		// No schema - either not a generic lsig or no args required
		if len(providedArgs) > 0 {
			// Args provided but no schema - might be an error, but let server handle it
			return nil
		}
		return nil
	}

	// Build a set of valid arg names from schema
	validNames := make(map[string]bool)
	for _, arg := range schema {
		validNames[arg.Name] = true
	}

	// Check all provided args have valid names
	for name := range providedArgs {
		if !validNames[name] {
			return fmt.Errorf("unknown argument '%s' for this account type", name)
		}
	}

	// Check all required args are provided
	var missing []string
	for _, arg := range schema {
		if arg.Required {
			if _, provided := providedArgs[arg.Name]; !provided {
				missing = append(missing, arg.Name)
			}
		}
	}

	if len(missing) > 0 {
		if len(missing) == 1 {
			return fmt.Errorf("missing required argument: %s", missing[0])
		}
		return fmt.Errorf("missing required arguments: %s", strings.Join(missing, ", "))
	}

	return nil
}

// IsAccountSignable checks if an account can be signed for with the available keys
// Returns true if either:
//   - The account is not rekeyed and we have its key on Signer
//   - The account is rekeyed to an address whose key we have on Signer
func IsAccountSignable(address string, signerCache *SignerCache, authCache *AuthAddressCache) bool {
	if signerCache == nil {
		return false
	}

	// Get the auth address (who needs to sign for this account)
	if authCache != nil {
		authAddr, hasRekey := authCache.GetAuthAddress(address)
		if hasRekey && authAddr != "" {
			// Rekeyed - check if we have the auth address's key
			return signerCache.HasAddress(authAddr)
		}
	}

	// No rekey (or no authCache provided) - check if we have the key directly
	return signerCache.HasAddress(address)
}
