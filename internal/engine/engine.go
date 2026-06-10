// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package engine provides the apshell-side application facade.
// It owns client-scoped state, signer connectivity, transaction orchestration,
// and execution modes used by shells, scripts, MCP, and other client entry
// points.
package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/addressbook"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientstate"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
)

// Engine is the client application facade for apshell-family frontends.
// It combines:
// - client-scoped caches and network state via clientstate.State
// - remote signer connection lifecycle via engine/connect
// - execution modes used during signing/submission
//
// Callers should treat it as the single owner for apshell-side application
// state, not as a transport-agnostic domain core.
type Engine struct {
	*clientstate.State
	Connection *connect.ConnectionState
	watcher    *clientstate.CacheWatcher

	// signerCacheMu guards State.SignerCache, the only cache mutated off the
	// command goroutine: the SSH-tunnel disconnect callback resets it from the
	// tunnel's monitor goroutine (handleConnectionClosed -> resetSignerCache).
	// All other State caches are command-goroutine-confined; see the
	// concurrency contract on clientstate.State.
	signerCacheMu             sync.RWMutex
	signerStatusMu            sync.Mutex
	signerStatusRevisionSeen  bool
	signerStatusKeysetRevSeen uint64

	// Remote Signing
	// Configuration
	WriteMode       bool
	Verbose         bool // Controls detailed signing output (default: false)
	Simulate        bool // Simulate mode: transactions are simulated instead of submitted (default: false)
	SentryEndpoints config.SentryEndpointConfigs
}

// EngineOption is a functional option for configuring the Engine
type EngineOption func(*Engine) error

// NewEngine creates a new Engine instance with the given network context token and options.
func NewEngine(network string, opts ...EngineOption) (*Engine, error) {
	e := &Engine{
		State:      clientstate.New(network),
		Connection: connect.NewState(),
		WriteMode:  false,
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, err
		}
	}

	return e, nil
}

// WithDataDir sets the client data directory for shared-state locking.
func WithDataDir(dataDir string) EngineOption {
	return func(e *Engine) error {
		e.DataDir = dataDir
		return nil
	}
}

// WithSentryEndpoints sets explicit sentry endpoint routing.
func WithSentryEndpoints(endpoints config.SentryEndpointConfigs) EngineOption {
	return func(e *Engine) error {
		e.SentryEndpoints = endpoints.Clone()
		return nil
	}
}

// WithAlgodClient sets the algod client for blockchain queries
func WithAlgodClient(client *algod.Client) EngineOption {
	return func(e *Engine) error {
		e.AlgodClient = client
		return nil
	}
}

// WithCacheStore sets the cache store used for disk-backed client caches.
func WithCacheStore(store *cache.Store) EngineOption {
	return func(e *Engine) error {
		e.CacheStore = store
		return nil
	}
}

// WithASACache sets the ASA cache
func WithASACache(cache cache.ASACache) EngineOption {
	return func(e *Engine) error {
		e.AsaCache = cache
		return nil
	}
}

// WithAliasCache sets the alias cache
func WithAliasCache(cache cache.AliasCache) EngineOption {
	return func(e *Engine) error {
		e.AliasCache = cache
		return nil
	}
}

// WithSignerCache sets the signer cache
func WithSignerCache(cache cache.SignerCache) EngineOption {
	return func(e *Engine) error {
		e.SignerCache = cache
		return nil
	}
}

// WithAuthCache sets the auth address cache
func WithAuthCache(cache cache.AuthAddressCache) EngineOption {
	return func(e *Engine) error {
		e.AuthCache = cache
		return nil
	}
}

// WithSetCache sets the set cache
func WithSetCache(cache cache.SetCache) EngineOption {
	return func(e *Engine) error {
		e.SetCache = cache
		return nil
	}
}

// SetWriteMode enables or disables transaction JSON file writing
func (e *Engine) SetWriteMode(enabled bool) {
	e.WriteMode = enabled
}

// GetWriteMode returns the current write mode state
func (e *Engine) GetWriteMode() bool {
	return e.WriteMode
}

// SetVerbose enables or disables detailed signing output
func (e *Engine) SetVerbose(enabled bool) {
	e.Verbose = enabled
}

// GetVerbose returns the current verbose mode state
func (e *Engine) GetVerbose() bool {
	return e.Verbose
}

// SetSimulate enables or disables transaction simulation mode
func (e *Engine) SetSimulate(enabled bool) {
	e.Simulate = enabled
}

// GetSimulate returns the current simulate mode state
func (e *Engine) GetSimulate() bool {
	return e.Simulate
}

// SetNetwork switches to a different Algorand network, updates the algod client,
// and rebuilds the ASA and auth caches for the new network.
func (e *Engine) SetNetwork(network string, algodClient *algod.Client) error {
	if err := config.ValidateNetworkID(network); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidNetwork, err)
	}

	e.Network = network
	e.AlgodClient = algodClient
	e.AsaCache = cache.LoadASACacheFromStore(e.CacheStore, network)
	// RLock covers the SignerCache read inside BuildAuthCache against a
	// concurrent disconnect reset; the cache assignments themselves are
	// command-goroutine-confined (see clientstate.State).
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	e.AuthCache = cache.BuildAuthCacheFromStore(e.CacheStore, algodClient, &e.AliasCache, &e.SignerCache, network)

	return nil
}

// GetNetwork returns the current network
func (e *Engine) GetNetwork() string {
	return e.Network
}

// StartClientCacheWatcher begins passive tracking of shared APCLIENT_DATA cache changes.
func (e *Engine) StartClientCacheWatcher() error {
	if e == nil || e.DataDir == "" || e.watcher != nil {
		return nil
	}
	watcher, err := clientstate.StartCacheWatcher(e.DataDir)
	if err != nil {
		return err
	}
	e.watcher = watcher
	return nil
}

// StopClientCacheWatcher stops passive APCLIENT_DATA cache tracking.
func (e *Engine) StopClientCacheWatcher() {
	if e == nil || e.watcher == nil {
		return
	}
	_ = e.watcher.Close()
	e.watcher = nil
}

// ApplyClientCacheUpdates reloads in-memory cache snapshots for files changed by another client.
func (e *Engine) ApplyClientCacheUpdates() error {
	if e == nil || e.watcher == nil {
		return nil
	}
	changes := e.watcher.Drain()
	if changes.Empty() {
		return nil
	}
	return e.withClientDataLock(func() error {
		if changes.Alias {
			e.ReloadAliasCache()
		}
		if changes.Set {
			e.ReloadSetCache()
		}
		if changes.Signer {
			e.signerCacheMu.Lock()
			e.ReloadSignerCache()
			e.signerCacheMu.Unlock()
		}
		if changes.ASA[e.Network] {
			e.ReloadASACache()
		}
		if changes.Auth[e.Network] {
			e.ReloadAuthCache()
		}
		return nil
	})
}

// NewAddressResolver creates an AddressResolver with dynamic sets (@signers, @all, @holders) enabled.
func (e *Engine) NewAddressResolver() *addressbook.Resolver {
	resolver := addressbook.NewResolver(&e.AliasCache, &e.SetCache)
	return resolver.WithSignerProvider(func() []string {
		signers := e.listSignersCached()
		addresses := make([]string, 0, len(signers))
		for addr := range signers {
			addresses = append(addresses, addr)
		}
		return addresses
	}).WithAllProvider(func() []string {
		return e.listAllAddressesCached()
	}).WithHoldersProvider(func(assetRef string) ([]string, error) {
		// The resolver interface carries no context; resolution happens on the
		// interactive command path where cancellation is not yet plumbed.
		result, err := e.GetHoldersWithContext(context.Background(), assetRef)
		if result == nil {
			return nil, err
		}
		return result.Addresses, err
	})
}

// collectAllAddresses returns a deduplicated set of all known addresses
// (from both the alias cache and the signer cache).
func (e *Engine) collectAllAddresses() map[string]bool {
	addressSet := make(map[string]bool)
	if e.AliasCache.Aliases != nil {
		for _, addr := range e.AliasCache.Aliases {
			addressSet[addr] = true
		}
	}
	for addr := range e.signerCacheKeysSnapshot() {
		addressSet[addr] = true
	}
	return addressSet
}

func (e *Engine) listAllAddressesCached() []string {
	addressSet := e.collectAllAddresses()
	addresses := make([]string, 0, len(addressSet))
	for addr := range addressSet {
		addresses = append(addresses, addr)
	}
	return addresses
}

// ListAllAddresses returns all known addresses (aliases + signer keys).
func (e *Engine) ListAllAddresses() ([]string, error) {
	if err := e.EnsureSignerCacheWithContext(context.Background()); err != nil {
		return nil, err
	}
	return e.listAllAddressesCached(), nil
}

// EnsureSignerCacheWithContext refreshes the signer cache from the connected
// signer if the cache is empty, using ctx for the inventory request.
func (e *Engine) EnsureSignerCacheWithContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !e.IsConnected() || e.signerCacheCount() > 0 {
		return nil
	}

	keysResp, err := e.GetKeysWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to refresh signer cache: %w", err)
	}

	if keysResp.Locked {
		e.setSignerCacheLockedFlag(true)
		return nil
	}

	if len(keysResp.Keys) == 0 {
		return nil
	}

	if err := e.withClientDataLock(func() error {
		return e.populateAndSaveSignerCacheUnderClientLock(keysResp.Keys)
	}); err != nil {
		cache.Debug("failed to save signer cache", "error", err)
		e.populateSignerCache(keysResp.Keys)
	}

	return nil
}

func (e *Engine) getSuggestedParamsWithFeeWithContext(ctx context.Context, fee uint64, useFlatFee bool) (types.SuggestedParams, error) {
	sp, err := e.AlgodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return types.SuggestedParams{}, fmt.Errorf("failed to get suggested params: %w", err)
	}
	if useFlatFee {
		sp.FlatFee = true
		sp.Fee = types.MicroAlgos(fee)
	}
	return sp, nil
}
