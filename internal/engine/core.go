// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/clientstate"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
)

// Core is the shared client infrastructure the Engine and its domain operations
// are built on: client-scoped caches and network state, remote signer
// connection lifecycle, the signer key cache, address/signability/asset
// resolution (including the read-only balance/holders queries the address
// resolver needs), and the client-data lock. Domain command methods (payments,
// asset transfers, apps, key management, guarded signing) live on Engine and
// reach this infrastructure through the embedded *Core.
type Core struct {
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
	consensusValidation       consensusValidationCache

	// Remote Signing
	// Configuration
	WriteMode        bool
	Verbose          bool // Controls detailed signing output (default: false)
	Simulate         bool // Simulate mode: transactions are simulated instead of submitted (default: false)
	EndpointRegistry config.ClientEndpointRegistry
}
