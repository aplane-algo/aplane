// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/util"
)

// GetASAInfo retrieves asset information by ID, using cache when available.
// Use forceRefresh=true to always fetch from network (needed for fields not in cache like Manager).
func (e *Engine) GetASAInfo(assetID uint64, forceRefresh ...bool) (*ASAInfo, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Check cache first (unless force refresh requested)
	refresh := len(forceRefresh) > 0 && forceRefresh[0]
	if !refresh && e.AsaCache.Assets != nil {
		if cached, ok := e.AsaCache.Assets[assetID]; ok {
			return &ASAInfo{
				AssetID:  assetID,
				UnitName: cached.UnitName,
				Name:     cached.Name,
				Decimals: cached.Decimals,
			}, nil
		}
	}

	// Fetch from algod
	assetInfo, err := e.AlgodClient.GetAssetByID(assetID).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get asset %d: %w", assetID, err)
	}

	defaultFrozen := assetInfo.Params.DefaultFrozen

	result := &ASAInfo{
		AssetID:       assetID,
		UnitName:      assetInfo.Params.UnitName,
		Name:          assetInfo.Params.Name,
		Decimals:      assetInfo.Params.Decimals,
		Total:         assetInfo.Params.Total,
		Creator:       assetInfo.Params.Creator,
		Manager:       assetInfo.Params.Manager,
		Reserve:       assetInfo.Params.Reserve,
		Freeze:        assetInfo.Params.Freeze,
		Clawback:      assetInfo.Params.Clawback,
		DefaultFrozen: defaultFrozen,
		URL:           assetInfo.Params.Url,
	}

	return result, nil
}

// AddASAToCache adds an asset to the cache (fetches info if not cached)
func (e *Engine) AddASAToCache(assetID uint64) (*ASAInfo, error) {
	info, err := e.GetASAInfo(assetID)
	if err != nil {
		return nil, err
	}

	// Add to cache
	e.cacheASA(info)
	return info, nil
}

// cacheASA adds an asset to the internal cache
func (e *Engine) cacheASA(info *ASAInfo) {
	if e.AsaCache.Assets == nil {
		e.AsaCache.Assets = make(map[uint64]util.ASAInfo)
	}
	e.AsaCache.Assets[info.AssetID] = util.ASAInfo{
		UnitName: info.UnitName,
		Name:     info.Name,
		Decimals: info.Decimals,
	}
}

// RemoveASAFromCache removes an asset from the cache
func (e *Engine) RemoveASAFromCache(assetID uint64) error {
	if e.AsaCache.Assets == nil {
		return fmt.Errorf("%w: %d", ErrInvalidAssetID, assetID)
	}
	if _, exists := e.AsaCache.Assets[assetID]; !exists {
		return fmt.Errorf("%w: %d not in cache", ErrInvalidAssetID, assetID)
	}
	delete(e.AsaCache.Assets, assetID)
	return nil
}

// ListCachedASAs returns all cached assets for current network
func (e *Engine) ListCachedASAs() []ASAInfo {
	if e.AsaCache.Assets == nil {
		return nil
	}

	var result []ASAInfo
	for id, cached := range e.AsaCache.Assets {
		result = append(result, ASAInfo{
			AssetID:  id,
			UnitName: cached.UnitName,
			Name:     cached.Name,
			Decimals: cached.Decimals,
		})
	}
	return result
}

// ResolveASAReference resolves an ASA reference (ID or unit name) to an ID
func (e *Engine) ResolveASAReference(asaRef string) (uint64, error) {
	return e.AsaCache.ResolveASAReference(asaRef, e.Network)
}

// ClearASACache clears all cached ASAs
func (e *Engine) ClearASACache() int {
	if e.AsaCache.Assets == nil {
		return 0
	}
	count := len(e.AsaCache.Assets)
	e.AsaCache.Assets = make(map[uint64]util.ASAInfo)
	return count
}
