// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Engine-side adapter for the isolated cosigned (cosigner) signing package.
// internal/engine/cosigned owns the orchestration and has no dependency on the
// engine; this file wires the engine's live connection, caches, and signer key
// cache into a cosigned.Signer, and re-exports the cosigned discovery types and
// sentinels so existing callers keep using the engine facade.

import (
	"context"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/cosigned"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// DiscoveredCosignerComponentKey is public cosigner-key metadata advertised by a
// signer endpoint through /keys.
type DiscoveredCosignerComponentKey = cosigned.DiscoveredCosignerComponentKey

// Cosigner discovery error sentinels, re-exported from the cosigned package so
// callers can classify failures via errors.Is without importing cosigned.
var (
	ErrCosignerDiscoveryInvalidMetadata = cosigned.ErrCosignerDiscoveryInvalidMetadata
	ErrCosignerDiscoveryUnavailable     = cosigned.ErrCosignerDiscoveryUnavailable
	ErrCosignerDiscoveryLocked          = cosigned.ErrCosignerDiscoveryLocked
	ErrCosignerDiscoveryAuth            = cosigned.ErrCosignerDiscoveryAuth
	ErrCosignerDiscoveryConfig          = cosigned.ErrCosignerDiscoveryConfig
)

// cosignedSignerCacheView adapts the engine's concurrency-cosigned signer key
// cache to the cosigned package's read-only SignerCacheView.
type cosignedSignerCacheView struct{ core *Core }

func (v cosignedSignerCacheView) AuthorizationKind(address string) (string, bool) {
	kind, present := v.core.signerCacheAuthorizationKind(address)
	if !present {
		return "", false
	}
	return string(kind), true
}

func (v cosignedSignerCacheView) SigningFlow(address string) string {
	return v.core.signerCacheSigningFlow(address)
}

func (v cosignedSignerCacheView) CosignerComponentKeyType(address string) (string, bool) {
	return v.core.signerCacheCosignerComponentKeyType(address)
}

func (v cosignedSignerCacheView) CosignerPublicKey(address string) (string, bool) {
	return v.core.signerCacheCosignerPublicKey(address)
}

func (v cosignedSignerCacheView) BoundedContract(address string) (string, bool) {
	return v.core.signerCacheBoundedContract(address)
}

func (v cosignedSignerCacheView) BoundedMaxFee(address string) (uint64, bool) {
	return v.core.signerCacheBoundedMaxFee(address)
}

func (v cosignedSignerCacheView) LogicSigResourceProfile(address string) (lsigresource.Profile, bool) {
	return v.core.signerCacheLogicSigResourceProfile(address)
}

// cosignedSigner builds a cosigned.Signer bound to the engine's live connection,
// auth cache, algod client, cosigner endpoints, and signer key cache. Construct
// one per operation; it holds no independent state.
func (e *Engine) cosignedSigner() *cosigned.Signer {
	return e.cosignedSignerWithHostKeyApproval(nil)
}

func (e *Engine) cosignedSignerWithHostKeyApproval(approve sshtunnel.HostKeyApprovalHandler) *cosigned.Signer {
	return cosigned.New(cosigned.Deps{
		Conn:             e.Connection,
		Algod:            e.AlgodClient,
		AuthCache:        &e.AuthCache,
		EndpointRegistry: e.EndpointRegistry,
		Cache:            cosignedSignerCacheView{e.Core},
		HostKeyApproval:  approve,
	})
}

// DiscoverCosignerComponentKeys queries one endpoint and returns cosigner component
// public keys that can be mapped for cosigned signing.
func (e *Engine) DiscoverCosignerComponentKeys(ctx context.Context, endpoint config.ClientEndpointConfig) ([]DiscoveredCosignerComponentKey, error) {
	return e.cosignedSigner().DiscoverCosignerComponentKeys(ctx, endpoint)
}

// DiscoverCosignerComponentKeysWithHostKeyApproval performs one explicit setup
// probe that may confirm an unknown SSH host. Normal background discovery does
// not install this callback and remains noninteractive.
func (e *Engine) DiscoverCosignerComponentKeysWithHostKeyApproval(ctx context.Context, endpoint config.ClientEndpointConfig, approve sshtunnel.HostKeyApprovalHandler) ([]DiscoveredCosignerComponentKey, error) {
	return e.cosignedSignerWithHostKeyApproval(approve).DiscoverCosignerComponentKeys(ctx, endpoint)
}

// CosignerEndpointInspection is the node role and cosigner key inventory one
// endpoint reported during guided setup.
type CosignerEndpointInspection = cosigned.EndpointInspection

// NodeRoleCosigner is the node role a cosigner endpoint reports.
const NodeRoleCosigner = cosigned.NodeRoleCosigner

// Route observation types and state names, re-exported so callers classify a
// CosignerStatus result through the engine facade.
type (
	CosignerRouteStatus             = cosigned.RouteStatus
	CosignerConnectionObservation   = cosigned.ConnectionObservation
	CosignerAccountRouteObservation = cosigned.AccountRouteObservation
)

const (
	CosignerConnectionNotChecked      = cosigned.ConnectionStateNotChecked
	CosignerConnectionReachable       = cosigned.ConnectionStateReachable
	CosignerConnectionHostKeyMismatch = cosigned.ConnectionStateHostKeyMismatch

	CosignerAccountRouteAvailable       = cosigned.AccountRouteAvailable
	CosignerAccountRouteMissing         = cosigned.AccountRouteMissing
	CosignerAccountRouteDuplicate       = cosigned.AccountRouteDuplicate
	CosignerAccountRouteCheckIncomplete = cosigned.AccountRouteCheckIncomplete
	CosignerAccountRouteInvalidMetadata = cosigned.AccountRouteInvalidMetadata
)

// InspectCosignerEndpointWithHostKeyApproval performs the explicit setup probe:
// it may confirm an unknown SSH host, reads the node role, and reads the key
// inventory only from a node that reports the cosigner role. It uses its own
// connection and never touches the primary signer connection.
func (e *Engine) InspectCosignerEndpointWithHostKeyApproval(ctx context.Context, endpoint config.ClientEndpointConfig, approve sshtunnel.HostKeyApprovalHandler) (CosignerEndpointInspection, error) {
	return e.cosignedSignerWithHostKeyApproval(approve).InspectCosignerEndpoint(ctx, endpoint)
}
