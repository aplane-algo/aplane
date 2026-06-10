// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

// JavaScript API functions for ASA (Algorand Standard Asset) operations:
// - Asset info and cache (assetInfo, cachedAssets, cacheAsset, uncacheAsset, clearAssetCache)
// - Well-known asset lookup (getAsaId)

import (
	"fmt"
	"strings"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/asa"
)

// jsAssetInfo returns information about an ASA.
// assetInfo(assetId) - Returns full ASA metadata
func (a *API) jsAssetInfo(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "assetInfo() requires an assetId argument")
	assetID := toUint64(a.runtime, call.Arguments[0])

	info, err := a.engine.GetASAInfoWithContext(a.Context(), assetID)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("assetInfo() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"assetId":       info.AssetID,
		"unitName":      info.UnitName,
		"name":          info.Name,
		"decimals":      info.Decimals,
		"total":         info.Total,
		"creator":       info.Creator,
		"manager":       info.Manager,
		"reserve":       info.Reserve,
		"freeze":        info.Freeze,
		"clawback":      info.Clawback,
		"defaultFrozen": info.DefaultFrozen,
		"url":           info.URL,
	})
}

// jsCachedAssets returns list of cached ASAs.
// cachedAssets() - Returns array of cached asset info
func (a *API) jsCachedAssets(call goja.FunctionCall) goja.Value {
	assets := a.engine.ListCachedASAs()

	result := make([]interface{}, len(assets))
	for i, info := range assets {
		result[i] = map[string]interface{}{
			"assetId":  info.AssetID,
			"unitName": info.UnitName,
			"name":     info.Name,
			"decimals": info.Decimals,
		}
	}
	return a.runtime.ToValue(result)
}

// jsCacheAsset adds an ASA to the cache.
// cacheAsset(assetId) - Fetches and caches asset info
func (a *API) jsCacheAsset(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "cacheAsset() requires an assetId argument")
	assetID := toUint64(a.runtime, call.Arguments[0])

	info, err := a.engine.AddASAToCache(a.Context(), assetID)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("cacheAsset() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"assetId":  info.AssetID,
		"unitName": info.UnitName,
		"name":     info.Name,
		"decimals": info.Decimals,
	})
}

// jsUncacheAsset removes an ASA from the cache.
// uncacheAsset(assetId) - Removes asset from cache
func (a *API) jsUncacheAsset(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "uncacheAsset() requires an assetId argument")
	assetID := toUint64(a.runtime, call.Arguments[0])

	err := a.engine.RemoveASAFromCache(assetID)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("uncacheAsset() error: %v", err)))
	}

	return a.runtime.ToValue(true)
}

// jsClearAssetCache clears all cached ASAs.
// clearAssetCache() - Removes all assets from cache, returns count
func (a *API) jsClearAssetCache(call goja.FunctionCall) goja.Value {
	count, err := a.engine.ClearASACache()
	if err != nil {
		panic(a.runtime.NewGoError(fmt.Errorf("failed to clear asset cache: %w", err)))
	}
	return a.runtime.ToValue(count)
}

// jsGetAsaId looks up an asset ID by ASA reference and network.
// getAsaId(name) - Returns asset ID for current network, or null if not found
// getAsaId(name, network) - Returns asset ID for specified network, or null if not found
func (a *API) jsGetAsaId(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "getAsaId() requires an asset name argument")
	name := strings.TrimSpace(call.Arguments[0].String())

	// Get network - use current network if not specified
	currentNetwork := strings.ToLower(strings.TrimSpace(a.engine.GetNetwork()))
	network := currentNetwork
	if len(call.Arguments) >= 2 {
		network = strings.ToLower(strings.TrimSpace(call.Arguments[1].String()))
	}

	resolver := a.engine.ASAResolver()
	if network != currentNetwork {
		resolver = asa.NewResolver(network, nil, nil)
	}
	assetID, err := resolver.ResolveID(name)
	if err != nil {
		return goja.Null()
	}

	return a.runtime.ToValue(assetID)
}
