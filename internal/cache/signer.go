// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// NewSignerCache creates an empty SignerCache
func NewSignerCache() SignerCache {
	cache := SignerCache{
		SchemaVersion:           cachePayloadSchemaVersion,
		Keys:                    make(map[string]string),
		GenericLsigs:            make(map[string]bool),
		LogicSigResources:       make(map[string]lsigresource.Profile),
		SigningArgs:             make(map[string][]SigningArgInfo),
		SigningFlows:            make(map[string]string),
		SentryComponentKeyTypes: make(map[string]string),
		SentryPublicKeys:        make(map[string]string),
		BoundedMaxFees:          make(map[string]uint64),
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
	delete(cache.LogicSigResources, address)
	delete(cache.SigningArgs, address)
	delete(cache.SigningFlows, address)
	delete(cache.SentryComponentKeyTypes, address)
	delete(cache.SentryPublicKeys, address)
	delete(cache.BoundedMaxFees, address)
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

// LogicSigResourceProfile returns a defensive copy of the address's complete
// LogicSig resource profile.
func (cache *SignerCache) LogicSigResourceProfile(address string) (lsigresource.Profile, bool) {
	if cache.LogicSigResources == nil {
		return lsigresource.Profile{}, false
	}
	profile, ok := cache.LogicSigResources[address]
	if !ok {
		return lsigresource.Profile{}, false
	}
	return profile.Clone(), true
}

// SetLogicSigResourceProfile stores a defensive copy of a complete profile.
func (cache *SignerCache) SetLogicSigResourceProfile(address string, profile lsigresource.Profile) {
	if cache.LogicSigResources == nil {
		cache.LogicSigResources = make(map[string]lsigresource.Profile)
	}
	cache.LogicSigResources[address] = profile.Clone()
}

// SigningFlowForAddress returns the signing choreography label the signer
// inventory reported for an address (e.g. "sentry1"). Empty means the
// ordinary /sign path.
func (cache *SignerCache) SigningFlowForAddress(address string) string {
	if cache.SigningFlows == nil {
		return ""
	}
	return cache.SigningFlows[address]
}

// SetSigningFlowForAddress stores or clears the signing choreography label
// for an address.
func (cache *SignerCache) SetSigningFlowForAddress(address, flow string) {
	if cache.SigningFlows == nil {
		cache.SigningFlows = make(map[string]string)
	}
	if flow == "" {
		delete(cache.SigningFlows, address)
		return
	}
	cache.SigningFlows[address] = flow
}

// GuardedSigningMetadataNeedsRefresh reports whether a cached signer row uses
// a built-in guarded key type but lacks the runtime flow metadata current
// signer inventory should publish. This is a cache freshness heuristic only:
// clients still route guarded signing from signing_flow, not from key_type.
func (cache *SignerCache) GuardedSigningMetadataNeedsRefresh(address string) bool {
	keyType := cache.GetKeyType(address)
	if !keytypes.IsGuardedAccountKeyType(keyType) {
		return false
	}
	flow := cache.SigningFlowForAddress(address)
	if flow == "" {
		return true
	}
	if flow != signerapi.SigningFlowSentry1 {
		return false
	}
	if _, ok := cache.SentryComponentKeyTypeForAddress(address); !ok {
		return true
	}
	if _, ok := cache.SentryPublicKeyForAddress(address); !ok {
		return true
	}
	return false
}

// SentryComponentKeyTypeForAddress returns the sentry component key type the
// signer inventory reported for a guarded account.
func (cache *SignerCache) SentryComponentKeyTypeForAddress(address string) (string, bool) {
	if cache.SentryComponentKeyTypes == nil {
		return "", false
	}
	value, ok := cache.SentryComponentKeyTypes[address]
	return value, ok && value != ""
}

// SetSentryComponentKeyTypeForAddress stores or clears the sentry component
// key type for a guarded account.
func (cache *SignerCache) SetSentryComponentKeyTypeForAddress(address, componentKeyType string) {
	if cache.SentryComponentKeyTypes == nil {
		cache.SentryComponentKeyTypes = make(map[string]string)
	}
	if componentKeyType == "" {
		delete(cache.SentryComponentKeyTypes, address)
		return
	}
	cache.SentryComponentKeyTypes[address] = componentKeyType
}

// SentryPublicKeyForAddress returns the sentry public key embedded in a
// guarded account LogicSig, when signer inventory exposed it.
func (cache *SignerCache) SentryPublicKeyForAddress(address string) (string, bool) {
	if cache.SentryPublicKeys == nil {
		return "", false
	}
	value, ok := cache.SentryPublicKeys[address]
	return value, ok && value != ""
}

// SetSentryPublicKeyForAddress stores or clears the embedded sentry public
// key for a guarded account.
func (cache *SignerCache) SetSentryPublicKeyForAddress(address, publicKeyHex string) {
	if cache.SentryPublicKeys == nil {
		cache.SentryPublicKeys = make(map[string]string)
	}
	if publicKeyHex == "" {
		delete(cache.SentryPublicKeys, address)
		return
	}
	cache.SentryPublicKeys[address] = publicKeyHex
}

// BoundedMaxFeeForAddress returns the on-chain fee ceiling advertised for a
// bounded account. The boolean distinguishes a valid zero ceiling from
// missing metadata.
func (cache *SignerCache) BoundedMaxFeeForAddress(address string) (uint64, bool) {
	if cache.BoundedMaxFees == nil {
		return 0, false
	}
	value, ok := cache.BoundedMaxFees[address]
	return value, ok
}

// SetBoundedMaxFeeForAddress stores the advertised bounded fee ceiling.
func (cache *SignerCache) SetBoundedMaxFeeForAddress(address string, maxFee uint64) {
	if cache.BoundedMaxFees == nil {
		cache.BoundedMaxFees = make(map[string]uint64)
	}
	cache.BoundedMaxFees[address] = maxFee
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
