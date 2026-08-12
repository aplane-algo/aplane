// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package guarded implements the client-side orchestration of APlane's
// two-party guarded (sentry) signing flow: building the canonical group,
// collecting user and sentry component signatures, requesting non-guarded
// signatures over the frozen bytes, and assembling the final signed group.
//
// It is deliberately isolated from internal/engine so the safety-critical
// guarded path has a small, checkable dependency surface (pinned by
// test/arch). It reaches client state only through the narrow SignerCacheView
// and the concrete connection/cache/algod values passed in Deps; it must not
// import internal/engine.
package guarded

import (
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/lsigresource"
)

const authorizationLogicSig = "logic_sig"

// SignerCacheView is the read-only view of the signer key cache that guarded
// orchestration needs: per-address signer-advertised metadata used to detect
// guarded targets and size LogicSig budgets. It is implemented by the engine
// over its concurrency-guarded signer cache.
type SignerCacheView interface {
	// AuthorizationKind returns the cached authorization envelope and whether
	// the address is present. A present address with an empty kind is invalid.
	AuthorizationKind(address string) (string, bool)
	// SigningFlow returns the signer-advertised signing_flow for an address,
	// or "" if the address is not a guarded key.
	SigningFlow(address string) string
	// SentryComponentKeyType returns the sentry component key type advertised
	// for a guarded account.
	SentryComponentKeyType(address string) (string, bool)
	// SentryPublicKey returns the sentry public key embedded in a guarded
	// account's LogicSig, as advertised in inventory.
	SentryPublicKey(address string) (string, bool)
	// BoundedMaxFee returns the advertised on-chain fee ceiling for a bounded
	// account.
	BoundedMaxFee(address string) (uint64, bool)
	// LogicSigResourceProfile returns the split resource contract derived from
	// the final compiled program and reviewed authorization paths.
	LogicSigResourceProfile(address string) (lsigresource.Profile, bool)
}

// Deps are the collaborators guarded orchestration needs from the client.
type Deps struct {
	Conn            *connect.ConnectionState
	Algod           *algod.Client
	AuthCache       *cache.AuthAddressCache
	SentryEndpoints config.SentryEndpointConfigs
	Cache           SignerCacheView
}

// Signer orchestrates the client side of guarded signing. Construct one per
// operation with New; it holds no mutable state of its own.
type Signer struct {
	conn            *connect.ConnectionState
	algod           *algod.Client
	authCache       *cache.AuthAddressCache
	sentryEndpoints config.SentryEndpointConfigs
	cache           SignerCacheView
}

// New builds a Signer from the given dependencies.
func New(d Deps) *Signer {
	return &Signer{
		conn:            d.Conn,
		algod:           d.Algod,
		authCache:       d.AuthCache,
		sentryEndpoints: d.SentryEndpoints,
		cache:           d.Cache,
	}
}
