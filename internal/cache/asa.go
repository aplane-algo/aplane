// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

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

	// Merge builtin ASAs first. A cached entry adds assets the table does not
	// know; it never replaces a built-in entry (see PreferBuiltin).
	for id, info := range asaregistry.AllBuiltinMetadata(network) {
		cache.Assets[id] = ASAInfo{
			Name:     info.Name,
			UnitName: info.UnitName,
			Decimals: info.Decimals,
		}
	}

	// Load cached ASAs and merge them under the built-in entries
	filecache := ASACache{SchemaVersion: cachePayloadSchemaVersion, Assets: make(map[uint64]ASAInfo)}
	filecache.bindStore(store)
	if err := loadSignedCacheWithKey(store, GetASACacheFilenameForStore(store, network), &filecache); err != nil {
		warnCacheLoadError("ASA cache", err)
		return cache
	}

	for id, info := range filecache.Assets {
		cache.Assets[id] = PreferBuiltin(network, id, info)
	}

	Debug("loaded ASA cache", "network", network, "entries", len(cache.Assets))
	return cache
}

// reportedDisagreements remembers which cache-versus-built-in disagreements
// have been reported, so a cache reloaded many times reports each once.
var reportedDisagreements sync.Map

// PreferBuiltin returns the built-in metadata for an asset when the table has
// it, and info otherwise. An asset's name, unit name and decimals are fixed on
// chain, so a fetched or cached entry that differs from the reviewed built-in
// entry is wrong, and its decimals would convert display amounts into the
// wrong base units. The disagreement is reported once per process.
func PreferBuiltin(network string, assetID uint64, info ASAInfo) ASAInfo {
	b, ok := asaregistry.BuiltinMetadata(network, assetID)
	if !ok {
		return info
	}
	builtin := ASAInfo{Name: b.Name, UnitName: b.UnitName, Decimals: b.Decimals}
	if info == builtin {
		return builtin
	}
	key := fmt.Sprintf("%s/%d/%+v", network, assetID, info)
	if _, seen := reportedDisagreements.LoadOrStore(key, struct{}{}); !seen {
		warnf("ASA %d on %s: metadata (%q, %q, %d decimals) differs from the built-in (%q, %q, %d decimals); using the built-in",
			assetID, network, info.Name, info.UnitName, info.Decimals, builtin.Name, builtin.UnitName, builtin.Decimals)
	}
	return builtin
}

// FetchASAParams reads an asset's on-chain parameters from algod.
func FetchASAParams(ctx context.Context, client *algod.Client, assetID uint64) (models.AssetParams, error) {
	asset, err := client.GetAssetByID(assetID).Do(ctx)
	if err != nil {
		return models.AssetParams{}, err
	}
	return asset.Params, nil
}

// ASAInfoFromParams keeps the parameters an ASA cache stores.
func ASAInfoFromParams(params models.AssetParams) ASAInfo {
	return ASAInfo{
		Decimals: params.Decimals,
		Name:     params.Name,
		UnitName: params.UnitName,
	}
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
	params, err := FetchASAParams(ctx, algodClient, assetID)
	if err != nil {
		return ASAInfo{}, fmt.Errorf("failed to get asset info for ASA %d on %s: %w", assetID, network, err)
	}
	info := ASAInfoFromParams(params)

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
	// A built-in alias joins the candidates rather than standing behind the
	// cache: anyone can create an ASA with any name, so a cached asset that
	// shares a built-in alias makes the reference ambiguous instead of
	// taking it over.
	if id, ok, err := asaregistry.ResolveReference(network, asaRef); err != nil {
		return 0, err
	} else if ok {
		matches[id] = struct{}{}
	}

	ids := sortedAssetIDs(matches)
	if len(ids) == 1 {
		return ids[0], nil
	}
	if len(ids) > 1 {
		return 0, fmt.Errorf("ASA reference '%s' is ambiguous on %s; matches asset IDs %s. Use the ASA ID explicitly", asaRef, network, formatAssetIDList(ids))
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
