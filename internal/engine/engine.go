// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package engine provides the core business logic for apshell, independent of any UI.
// It manages network connections, signing, transactions, and cache state.
package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/util"
)

// Engine contains all business logic and state, independent of any UI.
// It provides methods for querying balances, sending transactions, managing
// connections, and other operations that were previously in REPLState.
type Engine struct {
	// Network Configuration
	Network     string
	AlgodClient *algod.Client

	// Caches
	AsaCache    util.ASACache
	AliasCache  util.AliasCache
	SignerCache util.SignerCache
	AuthCache   util.AuthAddressCache
	SetCache    util.SetCache

	// Remote Signing
	SignerClient *util.SignerClient

	// Configuration
	WriteMode bool
	ConfigDir string
	Verbose   bool // Controls detailed signing output (default: false)
	Simulate  bool // Simulate mode: transactions are simulated instead of submitted (default: false)

	// Connection State (thread-safe)
	connMu           sync.Mutex
	sshTunnelClient  *sshtunnel.Client
	sshPort          int
	tunnelConnected  bool
	tunnelCtx        context.Context
	tunnelCancel     context.CancelFunc
	connectionTarget string
}

// EngineOption is a functional option for configuring the Engine
type EngineOption func(*Engine) error

// NewEngine creates a new Engine instance with the given network and options.
// The network should be one of "mainnet", "testnet", or "betanet".
func NewEngine(network string, opts ...EngineOption) (*Engine, error) {
	e := &Engine{
		Network:   network,
		WriteMode: false,
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, err
		}
	}

	return e, nil
}

// WithAlgodClient sets the algod client for blockchain queries
func WithAlgodClient(client *algod.Client) EngineOption {
	return func(e *Engine) error {
		e.AlgodClient = client
		return nil
	}
}

// WithASACache sets the ASA cache
func WithASACache(cache util.ASACache) EngineOption {
	return func(e *Engine) error {
		e.AsaCache = cache
		return nil
	}
}

// WithAliasCache sets the alias cache
func WithAliasCache(cache util.AliasCache) EngineOption {
	return func(e *Engine) error {
		e.AliasCache = cache
		return nil
	}
}

// WithSignerCache sets the signer cache
func WithSignerCache(cache util.SignerCache) EngineOption {
	return func(e *Engine) error {
		e.SignerCache = cache
		return nil
	}
}

// WithAuthCache sets the auth address cache
func WithAuthCache(cache util.AuthAddressCache) EngineOption {
	return func(e *Engine) error {
		e.AuthCache = cache
		return nil
	}
}

// WithSetCache sets the set cache
func WithSetCache(cache util.SetCache) EngineOption {
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

// SetNetwork switches to a different Algorand network
func (e *Engine) SetNetwork(network string, algodClient *algod.Client) error {
	validNetworks := []string{"mainnet", "testnet", "betanet"}
	isValid := false
	for _, n := range validNetworks {
		if network == n {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("%w: %s (valid: mainnet, testnet, betanet)", ErrInvalidNetwork, network)
	}

	e.Network = network
	e.AlgodClient = algodClient

	return nil
}

// GetNetwork returns the current network
func (e *Engine) GetNetwork() string {
	return e.Network
}

// NewAddressResolver creates an AddressResolver with dynamic sets (@signers, @all, @holders) enabled.
func (e *Engine) NewAddressResolver() *util.AddressResolver {
	resolver := util.NewAddressResolver(&e.AliasCache, &e.SetCache)
	return resolver.WithSignerProvider(func() []string {
		signers := e.ListSigners()
		addresses := make([]string, 0, len(signers))
		for addr := range signers {
			addresses = append(addresses, addr)
		}
		return addresses
	}).WithAllProvider(func() []string {
		return e.ListAllAddresses()
	}).WithHoldersProvider(func(assetRef string) ([]string, error) {
		return e.GetHolders(assetRef)
	})
}

// ListAllAddresses returns all known addresses (aliases + signer keys).
func (e *Engine) ListAllAddresses() []string {
	e.EnsureSignerCache()

	addressSet := make(map[string]bool)

	// Add all aliases
	if e.AliasCache.Aliases != nil {
		for _, addr := range e.AliasCache.Aliases {
			addressSet[addr] = true
		}
	}

	// Add all signer addresses
	if e.SignerCache.Keys != nil {
		for addr := range e.SignerCache.Keys {
			addressSet[addr] = true
		}
	}

	addresses := make([]string, 0, len(addressSet))
	for addr := range addressSet {
		addresses = append(addresses, addr)
	}
	return addresses
}

// EnsureSignerCache refreshes the signer cache from the connected signer if
// the cache is empty. This handles the case where keys were loaded on signer
// after the initial connection (e.g., signer was locked at connection time).
// Returns true if keys were refreshed, false otherwise.
// Sets SignerCache.Locked if the signer reports it is locked.
func (e *Engine) EnsureSignerCache() bool {
	if e.SignerClient == nil || e.SignerCache.Count() > 0 {
		return false
	}

	keysResp, err := e.SignerClient.GetKeys("")
	if err != nil {
		return false
	}

	if keysResp.Locked {
		e.SignerCache.Locked = true
		return false
	}

	if len(keysResp.Keys) == 0 {
		return false
	}

	e.SignerCache.Locked = false
	e.populateSignerCache(keysResp.Keys)
	e.SignerCache.Checksum = keysResp.Checksum

	return true
}

// getSuggestedParamsWithFee fetches suggested params and applies fee settings.
// If useFlatFee is true, sets FlatFee=true and uses the provided fee value.
// Otherwise, uses the network's suggested fee multiplier.
func (e *Engine) getSuggestedParamsWithFee(fee uint64, useFlatFee bool) (types.SuggestedParams, error) {
	sp, err := e.AlgodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return types.SuggestedParams{}, fmt.Errorf("failed to get suggested params: %w", err)
	}
	if useFlatFee {
		sp.FlatFee = true
		sp.Fee = types.MicroAlgos(fee)
	}
	return sp, nil
}
