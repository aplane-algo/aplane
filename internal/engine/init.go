// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/clientstate"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"

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
func NewInitializedEngine(network string, config *config.Config, dataDir string) *Engine {
	// Non-fatal if this fails - some operations work without algod
	// Caller can check if Engine.AlgodClient is nil if needed
	var algodClient *algod.Client
	if config != nil {
		algodClient, _ = algo.GetAlgodClientWithConfig(network, config)
	}

	return &Engine{
		Core: &Core{
			State:            clientstate.NewInitialized(network, dataDir, algodClient),
			Connection:       connect.NewState(),
			EndpointRegistry: configuredEndpointRegistry(config).Clone(),
		},
	}
}

func configuredEndpointRegistry(cfg *config.Config) config.ClientEndpointRegistry {
	if cfg == nil {
		return config.ClientEndpointRegistry{}
	}
	return cfg.Endpoints
}
