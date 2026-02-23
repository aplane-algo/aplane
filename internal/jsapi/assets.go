// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package jsapi

// JavaScript API functions for ASA (Algorand Standard Asset) operations:
// - Asset info and cache (assetInfo, cachedAssets, cacheAsset, uncacheAsset, clearAssetCache)
// - Well-known asset lookup (getAsaId)

import (
	"fmt"
	"strings"

	"github.com/dop251/goja"
)

// wellKnownAssets maps unit names to asset IDs per network.
// Keys are lowercase unit names.
var wellKnownAssets = map[string]map[string]uint64{
	"mainnet": {
		"usdc":  31566704,
		"usdt":  312769,
		"gobtc": 386192725,
		"goeth": 386195940,
		"gard":  684649988,
		"defly": 470842789,
		"vest":  700965019,
		"coop":  796425061,
		"ora":   1284444444,
		"chips": 388592191,
		"akita": 523683256,
		"pepe":  1096015467,
	},
	"testnet": {
		"usdc": 10458941,
		"usdt": 180447,
	},
	"betanet": {
		// Add betanet assets as needed
	},
}

// jsAssetInfo returns information about an ASA.
// assetInfo(assetId) - Returns full ASA metadata
func (a *API) jsAssetInfo(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "assetInfo() requires an assetId argument")
	assetID := toUint64(a.runtime, call.Arguments[0])

	info, err := a.engine.GetASAInfo(assetID)
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

	info, err := a.engine.AddASAToCache(assetID)
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
	count := a.engine.ClearASACache()
	return a.runtime.ToValue(count)
}

// jsGetAsaId looks up a well-known asset ID by name and network.
// getAsaId(name) - Returns asset ID for current network, or null if not found
// getAsaId(name, network) - Returns asset ID for specified network, or null if not found
func (a *API) jsGetAsaId(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "getAsaId() requires an asset name argument")
	name := strings.ToLower(call.Arguments[0].String())

	// Get network - use current network if not specified
	network := a.engine.GetNetwork()
	if len(call.Arguments) >= 2 {
		network = strings.ToLower(call.Arguments[1].String())
	}

	// Look up the asset
	networkAssets, ok := wellKnownAssets[network]
	if !ok {
		return goja.Null()
	}

	assetId, ok := networkAssets[name]
	if !ok {
		return goja.Null()
	}

	return a.runtime.ToValue(assetId)
}
