// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	asaregistry "github.com/aplane-algo/aplane/internal/asa/registry"
)

// GetASACacheFilenameForStore returns the ASA cache filename for a network in the provided store.
func GetASACacheFilenameForStore(store *Store, network string) string {
	return storePath(store, fmt.Sprintf("%s_asa_cache.json", network))
}

// LoadASACacheFromStore loads the ASA cache from the provided store and merges builtin ASAs.
func LoadASACacheFromStore(store *Store, network string) ASACache {
	cache := ASACache{SchemaVersion: cachePayloadSchemaVersion, Assets: make(map[uint64]ASAInfo)}
	cache.bindStore(store)

	// Merge builtin ASAs first (can be overridden by cached values)
	for id, info := range asaregistry.AllBuiltinMetadata(network) {
		cache.Assets[id] = ASAInfo{
			Name:     info.Name,
			UnitName: info.UnitName,
			Decimals: info.Decimals,
		}
	}

	// Load cached ASAs and merge (cached values override builtins)
	filecache := ASACache{SchemaVersion: cachePayloadSchemaVersion, Assets: make(map[uint64]ASAInfo)}
	filecache.bindStore(store)
	if err := loadSignedCacheWithKey(store, GetASACacheFilenameForStore(store, network), &filecache); err != nil {
		warnCacheLoadError("ASA cache", err)
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
	return saveSignedCacheWithKey(cache.store, GetASACacheFilenameForStore(cache.store, network), cache)
}

// SaveCacheLocked saves the ASA cache while the caller already holds the
// APCLIENT_DATA mutation lock.
func (cache *ASACache) SaveCacheLocked(network string) error {
	return saveSignedCacheWithoutClientLock(cache.store, GetASACacheFilenameForStore(cache.store, network), cache)
}

// GetASAInfo retrieves ASA information (from cache or network)
func (cache *ASACache) GetASAInfo(algodClient *algod.Client, assetID uint64, network string) (ASAInfo, error) {
	return cache.GetASAInfoWithContext(context.Background(), algodClient, assetID, network)
}

// GetASAInfoWithContext retrieves ASA information using the caller's context
// for the network fetch when the cache is cold.
func (cache *ASACache) GetASAInfoWithContext(ctx context.Context, algodClient *algod.Client, assetID uint64, network string) (ASAInfo, error) {
	if info, exists := cache.Assets[assetID]; exists {
		Debug("using cached ASA info", "asset_id", assetID, "network", network, "name", info.Name, "unit", info.UnitName, "decimals", info.Decimals)
		return info, nil
	}

	Debug("looking up ASA", "asset_id", assetID, "network", network)
	assetInfo, err := algodClient.GetAssetByID(assetID).Do(ctx)
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
		warnf("failed to save %s ASA cache: %v", network, err)
	}

	return info, nil
}

// ResolveASAReference resolves an ASA reference (ID or unit name) to an ID
func (cache *ASACache) ResolveASAReference(asaRef string, network string) (uint64, error) {
	// Try parsing as ID first
	if asaID, err := strconv.ParseUint(asaRef, 10, 64); err == nil {
		return asaID, nil
	}

	matches := make(map[uint64]struct{})
	for asaID, info := range cache.Assets {
		if equalAssetRef(info.UnitName, asaRef) || equalAssetRef(info.Name, asaRef) {
			matches[asaID] = struct{}{}
		}
	}
	ids := sortedAssetIDs(matches)
	if len(ids) == 1 {
		return ids[0], nil
	}
	if len(ids) > 1 {
		return 0, fmt.Errorf("ASA reference '%s' is ambiguous in %s cache; matches asset IDs %s. Use the ASA ID explicitly", asaRef, network, formatAssetIDList(ids))
	}

	if id, ok, err := asaregistry.ResolveReference(network, asaRef); err != nil {
		return 0, err
	} else if ok {
		return id, nil
	}

	return 0, fmt.Errorf("ASA reference '%s' not found in %s cache or built-ins. Use ASA ID or ensure the asset is cached by using 'info <asa_id>' first", asaRef, network)
}

func equalAssetRef(value, ref string) bool {
	return strings.TrimSpace(value) != "" && strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(ref))
}

func sortedAssetIDs(matches map[uint64]struct{}) []uint64 {
	ids := make([]uint64, 0, len(matches))
	for id := range matches {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func formatAssetIDList(ids []uint64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatUint(id, 10)
	}
	return strings.Join(parts, ", ")
}

// ResolveBuiltinASAReference resolves a builtin ASA by numeric ID, unit/name, or explicit alias.
func ResolveBuiltinASAReference(network, asaRef string) (uint64, bool) {
	assetID, ok, err := asaregistry.ResolveReference(network, asaRef)
	return assetID, ok && err == nil
}

// BuiltinASAUnitName returns the builtin unit name for an ASA when available.
func BuiltinASAUnitName(network string, asaID uint64) (string, bool) {
	return asaregistry.BuiltinUnitName(network, asaID)
}

// BuiltinASAInfo returns builtin metadata for an ASA when available.
func BuiltinASAInfo(network string, asaID uint64) (ASAInfo, bool) {
	info, ok := asaregistry.BuiltinMetadata(network, asaID)
	if !ok {
		return ASAInfo{}, false
	}
	return ASAInfo{
		Name:     info.Name,
		UnitName: info.UnitName,
		Decimals: info.Decimals,
	}, true
}
