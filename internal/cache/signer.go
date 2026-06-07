// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"fmt"
	"strings"
)

// NewSignerCache creates an empty SignerCache
func NewSignerCache() SignerCache {
	cache := SignerCache{
		SchemaVersion:      cachePayloadSchemaVersion,
		Keys:               make(map[string]string),
		GenericLsigs:       make(map[string]bool),
		LsigSizes:          make(map[string]int),
		SigningArgs:        make(map[string][]SigningArgInfo),
		AttestorPublicKeys: make(map[string]string),
	}
	return cache
}

// LoadSignerCacheFromStore loads the signer cache from the provided store.
func LoadSignerCacheFromStore(store *Store) SignerCache {
	cache := NewSignerCache()
	cache.bindStore(store)
	if err := loadSignedCacheWithKey(store, storePath(store, "signer_cache.json"), &cache); err != nil {
		warnCacheLoadError("signer cache", err)
	}
	return cache
}

// SaveCache saves the signer cache to disk with HMAC signature.
func (cache *SignerCache) SaveCache() error {
	return saveSignedCacheWithKey(cache.store, storePath(cache.store, "signer_cache.json"), cache)
}

// SaveCacheLocked saves the signer cache while the caller already holds the
// APCLIENT_DATA mutation lock.
func (cache *SignerCache) SaveCacheLocked() error {
	return saveSignedCacheWithoutClientLock(cache.store, storePath(cache.store, "signer_cache.json"), cache)
}

// HasAddress checks if Signer can sign for this address
func (cache *SignerCache) HasAddress(address string) bool {
	_, exists := cache.Keys[address]
	return exists
}

// GetKeyType returns the key type for an address ("aplane.falcon1024.v1" or "ed25519")
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
	delete(cache.GenericLsigs, address)
	delete(cache.LsigSizes, address)
	delete(cache.SigningArgs, address)
	delete(cache.AttestorPublicKeys, address)
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

// AttestorPublicKeyForAddress returns the attestor public key embedded in an
// guarded account LogicSig, when signer inventory exposed it.
func (cache *SignerCache) AttestorPublicKeyForAddress(address string) (string, bool) {
	if cache.AttestorPublicKeys == nil {
		return "", false
	}
	value, ok := cache.AttestorPublicKeys[address]
	return value, ok && value != ""
}

// SetAttestorPublicKeyForAddress stores or clears the embedded attestor public
// key for a guarded account.
func (cache *SignerCache) SetAttestorPublicKeyForAddress(address, publicKeyHex string) {
	if cache.AttestorPublicKeys == nil {
		cache.AttestorPublicKeys = make(map[string]string)
	}
	if publicKeyHex == "" {
		delete(cache.AttestorPublicKeys, address)
		return
	}
	cache.AttestorPublicKeys[address] = publicKeyHex
}

// GetSigningArgs returns the key-file signing args schema for a LogicSig address.
// Returns nil if address is not in cache or has no signing args.
func (cache *SignerCache) GetSigningArgs(address string) []SigningArgInfo {
	if cache.SigningArgs == nil {
		return nil
	}
	return cache.SigningArgs[address]
}

// SetSigningArgs sets the key-file signing args schema for a LogicSig address.
func (cache *SignerCache) SetSigningArgs(address string, args []SigningArgInfo) {
	if cache.SigningArgs == nil {
		cache.SigningArgs = make(map[string][]SigningArgInfo)
	}
	if len(args) > 0 {
		cache.SigningArgs[address] = args
	} else {
		delete(cache.SigningArgs, address)
	}
}

// ValidateLsigArgs validates that provided lsig args match the schema for a generic lsig address.
// Returns nil if valid, or an error describing what's wrong.
// Checks:
//   - All required args are provided
//   - All provided arg names are valid (exist in schema)
func (cache *SignerCache) ValidateLsigArgs(address string, providedArgs map[string][]byte) error {
	schema := cache.GetSigningArgs(address)
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

	// Check all required args are provided and validate byte lengths
	var missing []string
	for _, arg := range schema {
		val, provided := providedArgs[arg.Name]
		if arg.Required && !provided {
			missing = append(missing, arg.Name)
			continue
		}
		if provided && arg.ByteLength > 0 && len(val) != arg.ByteLength {
			return fmt.Errorf("argument '%s': expected %d bytes, got %d", arg.Name, arg.ByteLength, len(val))
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
