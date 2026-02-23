// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// GetASACacheFilename returns the ASA cache filename for a network
func GetASACacheFilename(network string) string {
	return getCachePath(fmt.Sprintf("%s_asa_cache.json", network))
}

// builtinASAs contains well-known ASAs that are always available without caching.
// These are merged into the cache at load time.
var builtinASAs = map[string]map[uint64]ASAInfo{
	"mainnet": {
		// Stablecoins
		31566704:  {Name: "USDC", UnitName: "USDC", Decimals: 6},
		312769:    {Name: "Tether USDt", UnitName: "USDt", Decimals: 6},
		672913181: {Name: "goUSD", UnitName: "goUSD", Decimals: 6},
		760037151: {Name: "xUSD", UnitName: "xUSD", Decimals: 6},
		465865291: {Name: "STBL", UnitName: "STBL", Decimals: 6},
		841126810: {Name: "STBL2", UnitName: "STBL2", Decimals: 6},
		227855942: {Name: "STASIS EURO", UnitName: "EURS", Decimals: 2},

		// Wrapped assets
		386192725:  {Name: "goBTC", UnitName: "goBTC", Decimals: 8},
		386195940:  {Name: "goETH", UnitName: "goETH", Decimals: 8},
		1058926737: {Name: "Wrapped BTC", UnitName: "WBTC", Decimals: 8},
		887406851:  {Name: "Wrapped Ether", UnitName: "WETH", Decimals: 8},
		887648583:  {Name: "Wrapped SOL", UnitName: "SOL", Decimals: 8},
		893309613:  {Name: "Wrapped AVAX", UnitName: "WAVAX", Decimals: 8},
		1200094857: {Name: "ChainLink Token", UnitName: "LINK", Decimals: 8},

		// Liquid staking / governance
		1134696561: {Name: "Governance xAlgo", UnitName: "xALGO", Decimals: 6},
		2537013734: {Name: "tALGO", UnitName: "TALGO", Decimals: 6},
		793124631:  {Name: "Governance Algo", UnitName: "gALGO", Decimals: 6},
		1185173782: {Name: "mALGO", UnitName: "mALGO", Decimals: 6},
		2400334372: {Name: "cAlgo", UnitName: "cAlgo", Decimals: 6},

		// Precious metals (Meld)
		246516580: {Name: "Meld Gold (g)", UnitName: "GOLD$", Decimals: 6},
		246519683: {Name: "Meld Silver (g)", UnitName: "SILVER$", Decimals: 6},

		// Bridge tokens
		2320775407: {Name: "Aramid VOI", UnitName: "aVoi", Decimals: 6},

		// DeFi / Governance tokens
		2200000000: {Name: "TINY", UnitName: "TINY", Decimals: 6},
		3203964481: {Name: "Folks Finance", UnitName: "FOLKS", Decimals: 6},
		1138500612: {Name: "GORA", UnitName: "GORA", Decimals: 9},
		849191641:  {Name: "Hesab Afghani", UnitName: "HAFN", Decimals: 2},
		849229386:  {Name: "Hesab USD", UnitName: "HUSD", Decimals: 2},
		470842789:  {Name: "Defly Token", UnitName: "DEFLY", Decimals: 6},
		700965019:  {Name: "Vestige", UnitName: "VEST", Decimals: 6},
		452399768:  {Name: "Vote Coin", UnitName: "Vote", Decimals: 6},
		796425061:  {Name: "Coop Coin", UnitName: "COOP", Decimals: 6},
		1732165149: {Name: "CompX Token", UnitName: "COMPX", Decimals: 6},
		393537671:  {Name: "ASA Stats Token", UnitName: "ASASTATS", Decimals: 6},

		// Popular community tokens
		2726252423: {Name: "Alpha Arcade", UnitName: "ALPHA", Decimals: 6},
		523683256:  {Name: "AKITA INU", UnitName: "AKTA", Decimals: 0},
	},
	"testnet": {
		10458941: {Name: "USDC", UnitName: "USDC", Decimals: 6},
		180447:   {Name: "Tether USDt", UnitName: "USDt", Decimals: 6},
	},
}

// LoadASACache loads the ASA cache from disk and merges builtin ASAs.
func LoadASACache(network string) ASACache {
	cache := ASACache{Assets: make(map[uint64]ASAInfo)}

	// Merge builtin ASAs first (can be overridden by cached values)
	if builtins, ok := builtinASAs[network]; ok {
		for id, info := range builtins {
			cache.Assets[id] = info
		}
	}

	// Load cached ASAs and merge (cached values override builtins)
	var filecache ASACache
	if err := loadSignedCacheWithKey(GetASACacheFilename(network), &filecache); err != nil {
		fmt.Printf("Warning: Failed to load ASA cache for %s: %v\n", network, err)
		return cache
	}

	for id, info := range filecache.Assets {
		cache.Assets[id] = info
	}

	Debug("loaded ASA cache", "network", network, "entries", len(cache.Assets))
	return cache
}

// SaveCache saves the ASA cache to disk
func (cache *ASACache) SaveCache(network string) error {
	return saveSignedCacheWithKey(GetASACacheFilename(network), cache)
}

// GetASAInfo retrieves ASA information (from cache or network)
func (cache *ASACache) GetASAInfo(algodClient *algod.Client, assetID uint64, network string) (ASAInfo, error) {
	if info, exists := cache.Assets[assetID]; exists {
		Debug("using cached ASA info", "asset_id", assetID, "network", network, "name", info.Name, "unit", info.UnitName, "decimals", info.Decimals)
		return info, nil
	}

	Debug("looking up ASA", "asset_id", assetID, "network", network)
	assetInfo, err := algodClient.GetAssetByID(assetID).Do(context.Background())
	if err != nil {
		return ASAInfo{}, fmt.Errorf("failed to get asset info for ASA %d on %s: %w", assetID, network, err)
	}

	info := ASAInfo{
		Decimals: assetInfo.Params.Decimals,
		Name:     assetInfo.Params.Name,
		UnitName: assetInfo.Params.UnitName,
	}

	cache.Assets[assetID] = info
	if err := cache.SaveCache(network); err != nil {
		fmt.Printf("Warning: failed to save %s ASA cache: %v\n", network, err)
	}

	return info, nil
}

// ResolveASAReference resolves an ASA reference (ID or unit name) to an ID
func (cache *ASACache) ResolveASAReference(asaRef string, network string) (uint64, error) {
	// Try parsing as ID first
	if asaID, err := strconv.ParseUint(asaRef, 10, 64); err == nil {
		return asaID, nil
	}

	// Search by unit name
	for asaID, info := range cache.Assets {
		if strings.EqualFold(info.UnitName, asaRef) {
			// fmt.Printf("Resolved unit name '%s' to ASA ID %d on %s\n", asaRef, asaID, network)
			return asaID, nil
		}
	}

	return 0, fmt.Errorf("ASA with unit name '%s' not found in %s cache. Use ASA ID or ensure the asset is cached by using 'info <asa_id>' first", asaRef, network)
}

// IsBuiltinASA returns true if the ASA is a builtin for the given network
func IsBuiltinASA(asaID uint64, network string) bool {
	if builtins, ok := builtinASAs[network]; ok {
		_, exists := builtins[asaID]
		return exists
	}
	return false
}

// ListASAs lists all cached ASAs
func (cache *ASACache) ListASAs(network string) {
	if len(cache.Assets) == 0 {
		fmt.Printf("No ASAs cached for %s\n", network)
		return
	}

	fmt.Printf("Cached ASAs for %s:\n", network)
	for asaID, info := range cache.Assets {
		marker := ""
		if IsBuiltinASA(asaID, network) {
			marker = " (builtin)"
		}
		fmt.Printf("  %d: %s (%s) - %d decimals%s\n", asaID, info.Name, info.UnitName, info.Decimals, marker)
	}
}

// RemoveASA removes an ASA from the cache (builtins cannot be removed)
func (cache *ASACache) RemoveASA(asaID uint64, network string) error {
	if _, exists := cache.Assets[asaID]; !exists {
		return fmt.Errorf("ASA %d not found in %s cache", asaID, network)
	}

	if IsBuiltinASA(asaID, network) {
		return fmt.Errorf("ASA %d is a builtin and cannot be removed", asaID)
	}

	asaInfo := cache.Assets[asaID]
	delete(cache.Assets, asaID)

	if err := cache.SaveCache(network); err != nil {
		return fmt.Errorf("failed to save %s ASA cache: %w", network, err)
	}

	fmt.Printf("Removed ASA %d (%s) from %s cache\n", asaID, asaInfo.UnitName, network)
	return nil
}

// ClearCache clears the ASA cache
func (cache *ASACache) ClearCache(network string) error {
	count := len(cache.Assets)
	cache.Assets = make(map[uint64]ASAInfo)

	if err := cache.SaveCache(network); err != nil {
		return fmt.Errorf("failed to save %s ASA cache: %w", network, err)
	}

	fmt.Printf("Cleared %d ASAs from %s cache\n", count, network)
	return nil
}
