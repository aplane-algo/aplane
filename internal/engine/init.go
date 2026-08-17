// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/clientstate"
	"github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// NewInitializedEngine creates a new Engine with all caches and clients initialized.
// This is the preferred way to create an Engine for a new session.
//
// The Engine returned is the single source of truth for all shared state.
// UI layers (REPL, TUI, CLI) should access state via the Engine, not duplicate it.
//
// If config is provided, algod client is created from config settings.
// If config is nil or algod is not configured, AlgodClient will be nil.
func NewInitializedEngine(network string, config *config.Config, dataDir string) (*Engine, error) {
	// Create algod client for blockchain queries
	// Non-fatal if this fails - some operations work without algod
	// Caller can check if Engine.AlgodClient is nil if needed
	var algodClient *algod.Client
	if config != nil {
		algodClient, _ = algo.GetAlgodClientWithConfig(network, config)
	}

	state := clientstate.NewInitialized(network, dataDir, algodClient)

	// Create engine with all caches
	eng, err := NewEngine(network,
		WithAlgodClient(algodClient),
		WithDataDir(state.DataDir),
		WithEndpointRegistry(configuredEndpointRegistry(config)),
		WithCacheStore(state.CacheStore),
		WithASACache(state.AsaCache),
		WithAliasCache(state.AliasCache),
		WithSignerCache(state.SignerCache),
		WithAuthCache(state.AuthCache),
		WithSetCache(state.SetCache),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}

	return eng, nil
}

func configuredEndpointRegistry(cfg *config.Config) config.ClientEndpointRegistry {
	if cfg == nil {
		return config.ClientEndpointRegistry{}
	}
	return cfg.Endpoints
}
