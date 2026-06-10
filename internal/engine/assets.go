// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
)

// GetASAInfoWithContext retrieves asset information by ID, using the caller's
// context for network refreshes.
func (e *Engine) GetASAInfoWithContext(ctx context.Context, assetID uint64, forceRefresh ...bool) (*ASAInfo, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	refresh := len(forceRefresh) > 0 && forceRefresh[0]
	if refresh {
		assetInfo, err := e.AlgodClient.GetAssetByID(assetID).Do(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get asset %d: %w", assetID, err)
		}
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
			DefaultFrozen: assetInfo.Params.DefaultFrozen,
			URL:           assetInfo.Params.Url,
		}
		e.cacheASA(result)
		return result, nil
	}

	meta, err := e.ASAResolver().MetadataByID(assetID)
	if err == nil && meta.Source != asa.SourceIDOnly {
		return &ASAInfo{
			AssetID:  meta.AssetID,
			UnitName: meta.UnitName,
			Name:     meta.Name,
			Decimals: meta.Decimals,
		}, nil
	}

	info, err := e.AsaCache.GetASAInfoWithContext(ctx, e.AlgodClient, assetID, e.Network)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset %d: %w", assetID, err)
	}
	return &ASAInfo{
		AssetID:  assetID,
		UnitName: info.UnitName,
		Name:     info.Name,
		Decimals: info.Decimals,
	}, nil
}

// ASAResolver returns a shared ASA metadata/reference resolver for the engine's current network.
func (e *Engine) ASAResolver() asa.Resolver {
	return asa.NewResolver(e.Network, &e.AsaCache, e.AlgodClient)
}

// SaveASACache persists the ASA cache to disk for the current network.
func (e *Engine) SaveASACache() error {
	return e.withClientDataLock(func() error {
		if e.DataDir != "" {
			e.AsaCache = cache.LoadASACacheFromStore(e.CacheStore, e.Network)
		}
		return e.AsaCache.SaveCacheLocked(e.Network)
	})
}

func (e *Engine) AddASAToCacheWithContext(ctx context.Context, assetID uint64) (*ASAInfo, error) {
	info, err := e.GetASAInfoWithContext(ctx, assetID)
	if err != nil {
		return nil, err
	}

	err = e.withClientDataLock(func() error {
		if e.DataDir != "" {
			e.AsaCache = cache.LoadASACacheFromStore(e.CacheStore, e.Network)
		}
		e.cacheASA(info)
		return e.AsaCache.SaveCacheLocked(e.Network)
	})
	if err != nil {
		return info, fmt.Errorf("added to cache but failed to save: %w", err)
	}
	return info, nil
}

// cacheASA adds an asset to the internal cache
func (e *Engine) cacheASA(info *ASAInfo) {
	if e.AsaCache.Assets == nil {
		e.AsaCache.Assets = make(map[uint64]cache.ASAInfo)
	}
	e.AsaCache.Assets[info.AssetID] = cache.ASAInfo{
		UnitName: info.UnitName,
		Name:     info.Name,
		Decimals: info.Decimals,
	}
}

// RemoveASAFromCache removes an asset from the cache and persists the change.
func (e *Engine) RemoveASAFromCache(assetID uint64) error {
	return e.withClientDataLock(func() error {
		if e.DataDir != "" {
			e.AsaCache = cache.LoadASACacheFromStore(e.CacheStore, e.Network)
		}
		if e.AsaCache.Assets == nil {
			return fmt.Errorf("%w: %d", ErrInvalidAssetID, assetID)
		}
		if _, exists := e.AsaCache.Assets[assetID]; !exists {
			return fmt.Errorf("%w: %d not in cache", ErrInvalidAssetID, assetID)
		}
		delete(e.AsaCache.Assets, assetID)
		if err := e.AsaCache.SaveCacheLocked(e.Network); err != nil {
			return fmt.Errorf("removed from cache but failed to save: %w", err)
		}
		return nil
	})
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
	return e.ASAResolver().ResolveID(asaRef)
}

// ClearASACache clears all cached ASAs and persists the change.
// Returns the number of entries cleared and any save error.
func (e *Engine) ClearASACache() (int, error) {
	var count int
	err := e.withClientDataLock(func() error {
		if e.DataDir != "" {
			e.AsaCache = cache.LoadASACacheFromStore(e.CacheStore, e.Network)
		}
		if e.AsaCache.Assets == nil {
			return nil
		}
		count = len(e.AsaCache.Assets)
		e.AsaCache.Assets = make(map[uint64]cache.ASAInfo)
		return e.AsaCache.SaveCacheLocked(e.Network)
	})
	if err != nil {
		return count, fmt.Errorf("cleared cache but failed to save: %w", err)
	}
	return count, nil
}
