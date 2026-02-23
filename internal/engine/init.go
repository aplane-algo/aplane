// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/util"

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
func NewInitializedEngine(network string, config *util.Config) (*Engine, error) {
	// Create algod client for blockchain queries
	// Non-fatal if this fails - some operations work without algod
	// Caller can check if Engine.AlgodClient is nil if needed
	var algodClient *algod.Client
	if config != nil {
		algodClient, _ = algo.GetAlgodClientWithConfig(network, config)
	}

	// Load caches from disk
	asaCache := util.LoadASACache(network)
	aliasCache := util.LoadAliasCache()
	setCache := util.LoadSetCache()

	// SignerCache is empty until connected to Signer
	signerCache := util.NewSignerCache()
	signerCache.SetColorFormatter(algorithm.GetDisplayColor)

	// AuthCache depends on other caches
	authCache := util.BuildAuthCache(algodClient, &aliasCache, &signerCache, network)

	// Create engine with all caches
	eng, err := NewEngine(network,
		WithAlgodClient(algodClient),
		WithASACache(asaCache),
		WithAliasCache(aliasCache),
		WithSignerCache(signerCache),
		WithAuthCache(authCache),
		WithSetCache(setCache),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}

	return eng, nil
}
