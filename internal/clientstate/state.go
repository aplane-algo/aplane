// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientstate

import (
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientdata"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// State owns client-side caches and other APCLIENT_DATA-scoped runtime state.
//
// Concurrency contract: the caches are NOT internally synchronized. All five
// are confined to the host's single command goroutine (REPL loop, bubbletea
// Update, serialized MCP dispatch, JS runtime). The one exception is
// SignerCache, which the SSH-tunnel disconnect callback resets from its
// monitor goroutine — every cross-goroutine SignerCache access must therefore
// go through engine.Engine's signerCacheMu wrappers. Cross-process consistency
// is provided by the signed cache files together with WithExclusiveLock.
type State struct {
	DataDir string
	Network string

	AlgodClient *algod.Client
	CacheStore  *cache.Store

	AsaCache    cache.ASACache
	AliasCache  cache.AliasCache
	SignerCache cache.SignerCache
	AuthCache   cache.AuthAddressCache
	SetCache    cache.SetCache
}

// New creates an empty client state for the selected network.
func New(network string) *State {
	return &State{
		Network:     network,
		SignerCache: cache.NewSignerCache(),
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
	state.SignerCache = cache.LoadSignerCacheFromStore(state.CacheStore)
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

// SaveApshellToken persists the client auth token under APCLIENT_DATA.
func (s *State) SaveApshellToken(token string) (string, error) {
	tokenPath, err := tokenfile.GetApshellTokenPathForDataDir(s.DataDir)
	if err != nil {
		return "", err
	}
	return s.SaveApshellTokenToPath(tokenPath, token)
}

// SaveApshellTokenToPath persists a client auth token to a specific endpoint
// token file under APCLIENT_DATA.
func (s *State) SaveApshellTokenToPath(tokenPath, token string) (string, error) {
	if err := s.WithExclusiveLock(func() error {
		if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
			return err
		}
		return tokenfile.WriteToken(tokenPath, token)
	}); err != nil {
		return "", err
	}
	return tokenPath, nil
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
	s.SignerCache = cache.LoadSignerCacheFromStore(s.CacheStore)
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

// PopulateSignerCache rebuilds the signer cache from signer key metadata.
func (s *State) PopulateSignerCache(keys []signerapi.KeyInfo) {
	s.SignerCache.Keys = make(map[string]string, len(keys))
	s.SignerCache.GenericLsigs = make(map[string]bool)
	s.SignerCache.LogicSigResources = make(map[string]lsigresource.Profile)
	s.SignerCache.SigningArgs = make(map[string][]cache.SigningArgInfo)
	s.SignerCache.SigningFlows = make(map[string]string)
	s.SignerCache.SentryComponentKeyTypes = make(map[string]string)
	s.SignerCache.SentryPublicKeys = make(map[string]string)
	s.SignerCache.BoundedMaxFees = make(map[string]uint64)
	s.SignerCache.Locked = false
	s.SignerCache.BindStore(s.CacheStore)
	for _, keyInfo := range keys {
		s.SignerCache.Keys[keyInfo.Address] = keyInfo.KeyType

		if keyInfo.LogicSigResources != nil {
			if profile, ok := internalLogicSigResourceProfile(keyInfo.LogicSigResources); ok {
				s.SignerCache.SetLogicSigResourceProfile(keyInfo.Address, profile)
			}
		}
		if keyInfo.IsGenericLsig {
			s.SignerCache.SetGenericLsig(keyInfo.Address, true)
		}
		if keyInfo.SigningFlow != "" {
			s.SignerCache.SetSigningFlowForAddress(keyInfo.Address, keyInfo.SigningFlow)
		}
		if keyInfo.SentryComponentKeyType != "" {
			s.SignerCache.SetSentryComponentKeyTypeForAddress(keyInfo.Address, keyInfo.SentryComponentKeyType)
		}
		sentryPublicKey := keyInfo.Parameters[keytypes.ParameterSentryPublicKey]
		if sentryPublicKey == "" && keyInfo.BoundedAuthorization != nil && keyInfo.BoundedAuthorization.Sentry != nil {
			sentryPublicKey = keyInfo.BoundedAuthorization.Sentry.PublicKeyHex
		}
		if sentryPublicKey != "" {
			s.SignerCache.SetSentryPublicKeyForAddress(keyInfo.Address, sentryPublicKey)
		}
		if keyInfo.BoundedAuthorization != nil {
			s.SignerCache.SetBoundedMaxFeeForAddress(keyInfo.Address, keyInfo.BoundedAuthorization.MaxFee)
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
			s.SignerCache.SetSigningArgs(keyInfo.Address, signingArgs)
		}
	}
}

func internalLogicSigResourceProfile(profile *signerapi.LogicSigResourceProfile) (lsigresource.Profile, bool) {
	if profile == nil {
		return lsigresource.Profile{}, false
	}
	programBytes := uint64(0)
	path := func(usage *signerapi.LogicSigResourceUsage) *lsigresource.PathProfile {
		if usage == nil {
			return nil
		}
		if programBytes == 0 {
			programBytes = usage.ProgramBytes
		} else if programBytes != usage.ProgramBytes {
			programBytes = ^uint64(0)
		}
		return &lsigresource.PathProfile{ArgumentBytes: usage.ArgumentBytes, MaxOpcodeCost: usage.MaxOpcodeCost}
	}
	converted := lsigresource.Profile{
		Default:       path(profile.Default),
		Spend:         path(profile.Spend),
		SpendingRekey: path(profile.SpendingRekey),
		AdminRekey:    path(profile.AdminRekey),
	}
	if programBytes == 0 || programBytes == ^uint64(0) {
		return lsigresource.Profile{}, false
	}
	converted.ProgramBytes = programBytes
	return converted, true
}

// SaveSignerCache persists the signer cache to disk under APCLIENT_DATA.
func (s *State) SaveSignerCache() error {
	if s.CacheStore == nil {
		return nil
	}
	s.SignerCache.BindStore(s.CacheStore)
	return s.SignerCache.SaveCache()
}

// SaveSignerCacheLocked persists the signer cache while the caller already
// holds the shared APCLIENT_DATA mutation lock.
func (s *State) SaveSignerCacheLocked() error {
	if s.CacheStore == nil {
		return nil
	}
	s.SignerCache.BindStore(s.CacheStore)
	return s.SignerCache.SaveCacheLocked()
}
