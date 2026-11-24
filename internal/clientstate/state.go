// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientstate

import (
	"fmt"
	"maps"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientdata"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// State owns client-side caches and other APCLIENT_DATA-scoped runtime state.
//
// Concurrency contract: AsaCache, AliasCache, AuthCache, and SetCache are NOT
// internally synchronized; they are confined to the host's single command
// goroutine (REPL loop, bubbletea Update, serialized MCP dispatch, JS runtime).
// The one exception is the signer cache, which the SSH-tunnel disconnect
// callback resets from its monitor goroutine; State keeps it unexported behind
// signerCacheMu so every reader and writer takes the lock. Cross-process
// consistency is provided by the signed cache files together with
// WithExclusiveLock. Lock ordering: always acquire WithExclusiveLock before
// signerCacheMu, never the reverse.
type State struct {
	DataDir string
	Network string

	AlgodClient *algod.Client
	CacheStore  *cache.Store

	AsaCache   cache.ASACache
	AliasCache cache.AliasCache
	AuthCache  cache.AuthAddressCache
	SetCache   cache.SetCache

	signerCacheMu sync.RWMutex
	signerCache   cache.SignerCache
}

// New creates an empty client state for the selected network.
func New(network string) *State {
	return &State{
		Network:     network,
		signerCache: cache.NewSignerCache(),
	}
}

// NewInitialized creates a client state with caches loaded from disk.
func NewInitialized(network, dataDir string, algodClient *algod.Client) *State {
	state := New(network)
	state.DataDir = dataDir
	state.AlgodClient = algodClient
	state.CacheStore = cache.NewStore(dataDir)
	state.AsaCache = cache.LoadASACacheFromStore(state.CacheStore, network)
	state.AliasCache = cache.LoadAliasCacheFromStore(state.CacheStore)
	state.signerCache = cache.LoadSignerCacheFromStore(state.CacheStore)
	state.SetCache = cache.LoadSetCacheFromStore(state.CacheStore)
	state.AuthCache = cache.LoadAuthCacheFromStore(state.CacheStore, network)
	return state
}

// WithExclusiveLock serializes mutations to shared client-side state.
func (s *State) WithExclusiveLock(fn func() error) error {
	if s.DataDir == "" {
		return fn()
	}
	return clientdata.WithExclusiveLock(s.DataDir, fn)
}

// ReloadAliasCache refreshes aliases from disk-backed cache state.
func (s *State) ReloadAliasCache() {
	if s.DataDir == "" {
		return
	}
	s.AliasCache = cache.LoadAliasCacheFromStore(s.CacheStore)
}

// ReloadSetCache refreshes sets from disk-backed cache state.
func (s *State) ReloadSetCache() {
	if s.DataDir == "" {
		return
	}
	s.SetCache = cache.LoadSetCacheFromStore(s.CacheStore)
}

// ReloadSignerCache refreshes signer inventory from disk-backed cache state.
func (s *State) ReloadSignerCache() {
	if s.DataDir == "" {
		return
	}
	loaded := cache.LoadSignerCacheFromStore(s.CacheStore)
	s.signerCacheMu.Lock()
	s.signerCache = loaded
	s.signerCacheMu.Unlock()
}

// ReloadASACache refreshes the current network's ASA metadata cache.
func (s *State) ReloadASACache() {
	if s.DataDir == "" {
		return
	}
	s.AsaCache = cache.LoadASACacheFromStore(s.CacheStore, s.Network)
}

// ReloadAuthCache refreshes the current network's auth-address cache.
func (s *State) ReloadAuthCache() {
	if s.DataDir == "" {
		return
	}
	s.AuthCache = cache.LoadAuthCacheFromStore(s.CacheStore, s.Network)
}

// ApplyCacheChanges refreshes in-memory cache snapshots for changed cache files.
func (s *State) ApplyCacheChanges(changes CacheChanges) {
	if changes.Empty() {
		return
	}
	if changes.Alias {
		s.ReloadAliasCache()
	}
	if changes.Set {
		s.ReloadSetCache()
	}
	if changes.Signer {
		s.ReloadSignerCache()
	}
	if changes.ASA[s.Network] {
		s.ReloadASACache()
	}
	if changes.Auth[s.Network] {
		s.ReloadAuthCache()
	}
}

// PopulateSignerCache rebuilds the signer cache from signer key metadata. It
// validates every advertised LogicSig resource profile before mutating the
// existing cache so a malformed inventory cannot silently lose budgeting
// metadata or replace a previously valid snapshot.
func (s *State) PopulateSignerCache(keys []signerapi.KeyInfo) error {
	next, err := buildSignerCache(keys, s.CacheStore)
	if err != nil {
		return err
	}
	s.signerCacheMu.Lock()
	s.signerCache = next
	s.signerCacheMu.Unlock()
	return nil
}

// PopulateAndSaveSignerCacheLocked rebuilds the in-memory signer cache and
// persists that snapshot while the caller already holds the shared
// APCLIENT_DATA mutation lock. Disk I/O runs on a detached clone after
// releasing signerCacheMu so concurrent disconnects never wait on persistence.
func (s *State) PopulateAndSaveSignerCacheLocked(keys []signerapi.KeyInfo) error {
	next, err := buildSignerCache(keys, s.CacheStore)
	if err != nil {
		return err
	}
	toSave := next.Clone()
	toSave.BindStore(s.CacheStore)

	s.signerCacheMu.Lock()
	s.signerCache = next
	s.signerCacheMu.Unlock()

	return toSave.SaveCacheLocked()
}

func buildSignerCache(keys []signerapi.KeyInfo, store *cache.Store) (cache.SignerCache, error) {
	logicSigProfiles := make(map[string]lsigresource.Profile)
	for _, keyInfo := range keys {
		if keyInfo.LogicSigResources == nil {
			continue
		}
		profile, err := internalLogicSigResourceProfile(keyInfo.LogicSigResources)
		if err != nil {
			return cache.SignerCache{}, fmt.Errorf("key %s LogicSig resource profile: %w", keyInfo.Address, err)
		}
		logicSigProfiles[keyInfo.Address] = profile
	}

	next := cache.NewSignerCache()
	next.BindStore(store)
	for _, keyInfo := range keys {
		next.AddAddress(keyInfo.Address, keyInfo.KeyType, keyInfo.AuthorizationKind)

		if profile, ok := logicSigProfiles[keyInfo.Address]; ok {
			next.SetLogicSigResourceProfile(keyInfo.Address, profile)
		}
		if keyInfo.IsGenericLsig {
			next.SetGenericLsig(keyInfo.Address, true)
		}
		if keyInfo.SigningFlow != "" {
			next.SetSigningFlowForAddress(keyInfo.Address, keyInfo.SigningFlow)
		}
		if keyInfo.CosignerComponentKeyType != "" {
			next.SetCosignerComponentKeyTypeForAddress(keyInfo.Address, keyInfo.CosignerComponentKeyType)
		}
		if keyInfo.BoundedAuthorization != nil {
			if cosigner := keyInfo.BoundedAuthorization.Cosigner; cosigner != nil {
				next.SetCosignerPublicKeyForAddress(keyInfo.Address, cosigner.PublicKeyHex)
			}
			// A plain host has no fee ceiling; its contract says so.
			next.SetBoundedContractForAddress(keyInfo.Address, keyInfo.BoundedAuthorization.Contract)
			if keyInfo.BoundedAuthorization.MaxFee != nil {
				next.SetBoundedMaxFeeForAddress(keyInfo.Address, *keyInfo.BoundedAuthorization.MaxFee)
			}
		}
		if len(keyInfo.SigningArgs) > 0 {
			signingArgs := make([]cache.SigningArgInfo, len(keyInfo.SigningArgs))
			for i, arg := range keyInfo.SigningArgs {
				signingArgs[i] = cache.SigningArgInfo{
					Name:        arg.Name,
					Label:       arg.Label,
					Description: arg.Description,
					Type:        arg.Type,
					Required:    arg.Required,
					ByteLength:  arg.ByteLength,
					MaxSize:     arg.MaxSize,
				}
			}
			next.SetSigningArgs(keyInfo.Address, signingArgs)
		}
	}
	return next, nil
}

func internalLogicSigResourceProfile(profile *signerapi.LogicSigResourceProfile) (lsigresource.Profile, error) {
	if profile == nil {
		return lsigresource.Profile{}, fmt.Errorf("profile is missing")
	}
	hasDefault := profile.Default != nil
	boundedPaths := 0
	for _, usage := range []*signerapi.LogicSigResourceUsage{profile.Spend, profile.SpendingRekey, profile.ListedRekey} {
		if usage != nil {
			boundedPaths++
		}
	}
	if hasDefault && boundedPaths != 0 {
		return lsigresource.Profile{}, fmt.Errorf("default and bounded authorization paths cannot be mixed")
	}
	if !hasDefault && boundedPaths != 3 {
		return lsigresource.Profile{}, fmt.Errorf("bounded resource profile must contain spend, spending_rekey and listed_rekey paths")
	}

	var programBytes uint64
	seenProgram := false
	var conversionErr error
	path := func(name string, usage *signerapi.LogicSigResourceUsage) *lsigresource.PathProfile {
		if usage == nil {
			return nil
		}
		if usage.ProgramBytes == 0 {
			conversionErr = fmt.Errorf("%s program_bytes must be greater than zero", name)
			return nil
		}
		if usage.MaxOpcodeCost == 0 || usage.MaxOpcodeCost > lsigresource.MaximumDeclaredOpcodeCost {
			conversionErr = fmt.Errorf("%s max_opcode_cost must be between 1 and %d", name, lsigresource.MaximumDeclaredOpcodeCost)
			return nil
		}
		if !seenProgram {
			programBytes = usage.ProgramBytes
			seenProgram = true
		} else if programBytes != usage.ProgramBytes {
			conversionErr = fmt.Errorf("%s program_bytes %d does not match %d", name, usage.ProgramBytes, programBytes)
			return nil
		}
		return &lsigresource.PathProfile{ArgumentBytes: usage.ArgumentBytes, MaxOpcodeCost: usage.MaxOpcodeCost}
	}
	converted := lsigresource.Profile{
		Default:       path("default", profile.Default),
		Spend:         path("spend", profile.Spend),
		SpendingRekey: path("spending_rekey", profile.SpendingRekey),
		ListedRekey:   path("listed_rekey", profile.ListedRekey),
	}
	if conversionErr != nil {
		return lsigresource.Profile{}, conversionErr
	}
	if !seenProgram {
		return lsigresource.Profile{}, fmt.Errorf("profile has no authorization paths")
	}
	converted.ProgramBytes = programBytes
	return converted, nil
}

// SetSignerCache replaces the in-memory signer cache with a detached deep copy
// of next.
func (s *State) SetSignerCache(next cache.SignerCache) {
	cloned := next.Clone()
	cloned.BindStore(s.CacheStore)
	s.signerCacheMu.Lock()
	s.signerCache = cloned
	s.signerCacheMu.Unlock()
}

// ResetSignerCache replaces the in-memory signer cache with an empty cache
// carrying the given locked flag.
func (s *State) ResetSignerCache(locked bool) {
	next := cache.NewSignerCache()
	next.Locked = locked
	next.BindStore(s.CacheStore)
	s.signerCacheMu.Lock()
	s.signerCache = next
	s.signerCacheMu.Unlock()
}

// SetSignerCacheLocked updates the signer cache's locked flag.
func (s *State) SetSignerCacheLocked(locked bool) {
	s.signerCacheMu.Lock()
	s.signerCache.Locked = locked
	s.signerCacheMu.Unlock()
}

// SignerCacheSnapshot returns a detached deep copy of the signer cache under
// signerCacheMu.
func (s *State) SignerCacheSnapshot() cache.SignerCache {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.Clone()
}

// SignerCacheKeysSnapshot returns a copy of the cached address-to-key-type map.
func (s *State) SignerCacheKeysSnapshot() map[string]string {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return maps.Clone(s.signerCache.Keys)
}

// SignerCacheAddresses returns, in no set order, the addresses the signer
// cache lists: the signer's aplane keys as apshell last read them.
func (s *State) SignerCacheAddresses() []string {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	addresses := make([]string, 0, len(s.signerCache.Keys))
	for address := range s.signerCache.Keys {
		addresses = append(addresses, address)
	}
	return addresses
}

// SignerCacheCount returns the number of addresses in the signer cache.
func (s *State) SignerCacheCount() int {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.Count()
}

// SignerCacheLocked reports whether the signer last reported a locked state.
func (s *State) SignerCacheLocked() bool {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.Locked
}

// SignerCacheHasAddress reports whether address is listed in the signer cache.
func (s *State) SignerCacheHasAddress(address string) bool {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.HasAddress(address)
}

// SignerCacheKeyType returns the key type cached for address, or "" if absent.
func (s *State) SignerCacheKeyType(address string) string {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.GetKeyType(address)
}

// SignerCacheAlgorithm returns the cached key type for address, falling back to
// its cached auth address when rekeyed, or "unknown" if neither is listed.
func (s *State) SignerCacheAlgorithm(address string) string {
	authAddr, authExists := s.AuthCache.GetAuthAddress(address)

	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()

	if keyType, exists := s.signerCache.Keys[address]; exists {
		return keyType
	}
	if authExists && authAddr != "" {
		if keyType, exists := s.signerCache.Keys[authAddr]; exists {
			return keyType
		}
	}
	return "unknown"
}

// IsAccountSignable applies cache.IsAccountSignable, the rule the display
// marker uses too, under the signer cache lock.
func (s *State) IsAccountSignable(address string) bool {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return cache.IsAccountSignable(address, &s.signerCache, &s.AuthCache)
}

// SignerCacheAuthorizationKind returns the authorization kind the signer
// reported for an address on /keys, when this client knows it
// (SignerCache.AuthorizationKind). The boolean reports whether the address is
// present. A present address with an empty kind has none this client knows.
// The prepare path (BuildSigningContext, CanSignForAddressWithKind) refuses
// such a key, and cache.IsAccountSignable does not call it signable. A
// pre-built group reads no kind: it leaves its authorization to the signer,
// which holds the key.
func (s *State) SignerCacheAuthorizationKind(address string) (algorithm.AuthorizationKind, bool) {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	if !s.signerCache.HasAddress(address) {
		return "", false
	}
	return s.signerCache.AuthorizationKind(address), true
}

// SignerCacheLogicSigResourceProfile returns a defensive copy of the address's
// cached LogicSig resource profile.
func (s *State) SignerCacheLogicSigResourceProfile(address string) (lsigresource.Profile, bool) {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.LogicSigResourceProfile(address)
}

// SignerCacheSigningFlow returns the signing choreography label cached for
// address.
func (s *State) SignerCacheSigningFlow(address string) string {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.SigningFlowForAddress(address)
}

// SignerCacheCosignerComponentKeyType returns the cosigner component key type
// cached for a cosigned account.
func (s *State) SignerCacheCosignerComponentKeyType(address string) (string, bool) {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.CosignerComponentKeyTypeForAddress(address)
}

// SignerCacheCosignerPublicKey returns the cosigner public key cached for a
// cosigned account.
func (s *State) SignerCacheCosignerPublicKey(address string) (string, bool) {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.CosignerPublicKeyForAddress(address)
}

// SignerCacheBoundedContract returns the bounded authorization contract cached
// for address.
func (s *State) SignerCacheBoundedContract(address string) (string, bool) {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.BoundedContractForAddress(address)
}

// SignerCacheBoundedMaxFee returns the on-chain fee ceiling cached for address.
func (s *State) SignerCacheBoundedMaxFee(address string) (uint64, bool) {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.BoundedMaxFeeForAddress(address)
}

// SignerCacheIsGenericLsig reports whether address is cached as a generic
// LogicSig.
func (s *State) SignerCacheIsGenericLsig(address string) bool {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.IsGenericLsig(address)
}

// ValidateSignerLsigArgs validates provided LogicSig arguments against the
// schema cached for address.
func (s *State) ValidateSignerLsigArgs(address string, args map[string][]byte) error {
	s.signerCacheMu.RLock()
	defer s.signerCacheMu.RUnlock()
	return s.signerCache.ValidateLsigArgs(address, args)
}
