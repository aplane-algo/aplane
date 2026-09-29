// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Engine-side adapter for the isolated guarded (cosigner) signing package.
// internal/engine/guarded owns the orchestration and has no dependency on the
// engine; this file wires the engine's live connection, caches, and signer key
// cache into a guarded.Signer, and re-exports the guarded discovery types and
// sentinels so existing callers keep using the engine facade.

import (
	"context"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/guarded"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// DiscoveredCosignerComponentKey is public cosigner-key metadata advertised by a
// signer endpoint through /keys.
type DiscoveredCosignerComponentKey = guarded.DiscoveredCosignerComponentKey

// Cosigner discovery error sentinels, re-exported from the guarded package so
// callers can classify failures via errors.Is without importing guarded.
var (
	ErrCosignerDiscoveryInvalidMetadata = guarded.ErrCosignerDiscoveryInvalidMetadata
	ErrCosignerDiscoveryUnavailable     = guarded.ErrCosignerDiscoveryUnavailable
	ErrCosignerDiscoveryLocked          = guarded.ErrCosignerDiscoveryLocked
	ErrCosignerDiscoveryAuth            = guarded.ErrCosignerDiscoveryAuth
	ErrCosignerDiscoveryConfig          = guarded.ErrCosignerDiscoveryConfig
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

func (v guardedSignerCacheView) CosignerComponentKeyType(address string) (string, bool) {
	return v.core.signerCacheCosignerComponentKeyType(address)
}

func (v guardedSignerCacheView) CosignerPublicKey(address string) (string, bool) {
	return v.core.signerCacheCosignerPublicKey(address)
}

func (v guardedSignerCacheView) BoundedMaxFee(address string) (uint64, bool) {
	return v.core.signerCacheBoundedMaxFee(address)
}

func (v guardedSignerCacheView) LogicSigResourceProfile(address string) (lsigresource.Profile, bool) {
	return v.core.signerCacheLogicSigResourceProfile(address)
}

// guardedSigner builds a guarded.Signer bound to the engine's live connection,
// auth cache, algod client, cosigner endpoints, and signer key cache. Construct
// one per operation; it holds no independent state.
func (e *Engine) guardedSigner() *guarded.Signer {
	return e.guardedSignerWithHostKeyApproval(nil)
}

func (e *Engine) guardedSignerWithHostKeyApproval(approve sshtunnel.HostKeyApprovalHandler) *guarded.Signer {
	return guarded.New(guarded.Deps{
		Conn:             e.Connection,
		Algod:            e.AlgodClient,
		AuthCache:        &e.AuthCache,
		EndpointRegistry: e.EndpointRegistry,
		Cache:            guardedSignerCacheView{e.Core},
		HostKeyApproval:  approve,
	})
}

// DiscoverCosignerComponentKeys queries one endpoint and returns cosigner component
// public keys that can be mapped for guarded signing.
func (e *Engine) DiscoverCosignerComponentKeys(ctx context.Context, endpoint config.ClientEndpointConfig) ([]DiscoveredCosignerComponentKey, error) {
	return e.guardedSigner().DiscoverCosignerComponentKeys(ctx, endpoint)
}

// DiscoverCosignerComponentKeysWithHostKeyApproval performs one explicit setup
// probe that may confirm an unknown SSH host. Normal background discovery does
// not install this callback and remains noninteractive.
func (e *Engine) DiscoverCosignerComponentKeysWithHostKeyApproval(ctx context.Context, endpoint config.ClientEndpointConfig, approve sshtunnel.HostKeyApprovalHandler) ([]DiscoveredCosignerComponentKey, error) {
	return e.guardedSignerWithHostKeyApproval(approve).DiscoverCosignerComponentKeys(ctx, endpoint)
}
