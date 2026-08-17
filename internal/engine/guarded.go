// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Engine-side adapter for the isolated guarded (sentry) signing package.
// internal/engine/guarded owns the orchestration and has no dependency on the
// engine; this file wires the engine's live connection, caches, and signer key
// cache into a guarded.Signer, and re-exports the guarded discovery types and
// sentinels so existing callers keep using the engine facade.

import (
	"context"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/guarded"
	"github.com/aplane-algo/aplane/internal/lsigresource"
)

// DiscoveredSentryComponentKey is public sentry-key metadata advertised by a
// signer endpoint through /keys.
type DiscoveredSentryComponentKey = guarded.DiscoveredSentryComponentKey

// Sentry discovery error sentinels, re-exported from the guarded package so
// callers can classify failures via errors.Is without importing guarded.
var (
	ErrSentryDiscoveryInvalidMetadata = guarded.ErrSentryDiscoveryInvalidMetadata
	ErrSentryDiscoveryUnavailable     = guarded.ErrSentryDiscoveryUnavailable
	ErrSentryDiscoveryLocked          = guarded.ErrSentryDiscoveryLocked
	ErrSentryDiscoveryAuth            = guarded.ErrSentryDiscoveryAuth
	ErrSentryDiscoveryConfig          = guarded.ErrSentryDiscoveryConfig
)

// guardedSignerCacheView adapts the engine's concurrency-guarded signer key
// cache to the guarded package's read-only SignerCacheView.
type guardedSignerCacheView struct{ core *Core }

func (v guardedSignerCacheView) AuthorizationKind(address string) (string, bool) {
	kind, present := v.core.signerCacheAuthorizationKind(address)
	if !present {
		return "", false
	}
	return string(kind), true
}

func (v guardedSignerCacheView) SigningFlow(address string) string {
	return v.core.signerCacheSigningFlow(address)
}

func (v guardedSignerCacheView) SentryComponentKeyType(address string) (string, bool) {
	return v.core.signerCacheSentryComponentKeyType(address)
}

func (v guardedSignerCacheView) SentryPublicKey(address string) (string, bool) {
	return v.core.signerCacheSentryPublicKey(address)
}

func (v guardedSignerCacheView) BoundedMaxFee(address string) (uint64, bool) {
	return v.core.signerCacheBoundedMaxFee(address)
}

func (v guardedSignerCacheView) LogicSigResourceProfile(address string) (lsigresource.Profile, bool) {
	return v.core.signerCacheLogicSigResourceProfile(address)
}

// guardedSigner builds a guarded.Signer bound to the engine's live connection,
// auth cache, algod client, sentry endpoints, and signer key cache. Construct
// one per operation; it holds no independent state.
func (e *Engine) guardedSigner() *guarded.Signer {
	return guarded.New(guarded.Deps{
		Conn:             e.Connection,
		Algod:            e.AlgodClient,
		AuthCache:        &e.AuthCache,
		EndpointRegistry: e.EndpointRegistry,
		Cache:            guardedSignerCacheView{e.Core},
	})
}

// DiscoverSentryComponentKeys queries one endpoint and returns sentry component
// public keys that can be mapped for guarded signing.
func (e *Engine) DiscoverSentryComponentKeys(ctx context.Context, endpoint config.ClientEndpointConfig) ([]DiscoveredSentryComponentKey, error) {
	return e.guardedSigner().DiscoverSentryComponentKeys(ctx, endpoint)
}
