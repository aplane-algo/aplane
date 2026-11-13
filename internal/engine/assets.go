// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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
		params, err := cache.FetchASAParams(ctx, e.AlgodClient, assetID)
		if err != nil {
			return nil, fmt.Errorf("failed to get asset %d: %w", assetID, err)
		}
		result := &ASAInfo{
			AssetID:       assetID,
			UnitName:      params.UnitName,
			Name:          params.Name,
			Decimals:      params.Decimals,
			Total:         params.Total,
			Creator:       params.Creator,
			Manager:       params.Manager,
			Reserve:       params.Reserve,
			Freeze:        params.Freeze,
			Clawback:      params.Clawback,
			DefaultFrozen: params.DefaultFrozen,
			URL:           params.Url,
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
// It answers from the ASA cache, which is a display aid; a command that
// builds a transaction uses ASAResolverForTransaction.
func (e *Core) ASAResolver() asa.Resolver {
	return asa.NewResolver(e.Network, &e.AsaCache, e.AlgodClient)
}

// TransactionASAResolver resolves the asset of a transaction a command
// builds. It does not trust the ASA cache: an asset that is not built in is
// read from algod, and its cache entry is refreshed with what was read.
type TransactionASAResolver struct {
	ctx context.Context
	eng *Engine
}

// ASAResolverForTransaction returns the asset resolver for a command that
// builds a transaction. Display paths keep using ASAResolver.
func (e *Engine) ASAResolverForTransaction(ctx context.Context) TransactionASAResolver {
	return TransactionASAResolver{ctx: ctx, eng: e}
}

// ResolveMetadata resolves ref to the asset's metadata as algod reports it
// now. A built-in asset is answered from the reviewed table without a read.
// An asset named by name or unit name must still carry that name on the
// network; when it does not, its corrected cache entry is kept and the
// command is refused, because the name stood for another asset.
func (r TransactionASAResolver) ResolveMetadata(ref string) (asa.Metadata, error) {
	e := r.eng
	ref = strings.TrimSpace(ref)
	assetID, err := e.ASAResolver().ResolveID(ref)
	if err != nil {
		return asa.Metadata{}, err
	}
	if meta, ok := asa.BuiltinMetadata(e.Network, assetID); ok {
		return meta, nil
	}
	if e.AlgodClient == nil {
		return asa.Metadata{}, ErrNoAlgodClient
	}
	params, err := cache.FetchASAParams(r.ctx, e.AlgodClient, assetID)
	if err != nil {
		return asa.Metadata{}, fmt.Errorf("failed to get asset %d: %w", assetID, err)
	}
	live := cache.ASAInfoFromParams(params)
	refreshErr := e.refreshCachedASA(assetID, live)
	_, parseErr := strconv.ParseUint(ref, 10, 64)
	byName := parseErr != nil
	if byName && !live.MatchesReference(ref) {
		corrected := "the cache entry has been corrected"
		if refreshErr != nil {
			corrected = fmt.Sprintf("correcting the cache entry failed: %v", refreshErr)
		}
		return asa.Metadata{}, fmt.Errorf("the cached name %q no longer matches asset %d on %s, which is now %q (unit %q); %s. Check the asset and run the command again",
			ref, assetID, e.Network, live.Name, live.UnitName, corrected)
	}
	if refreshErr != nil {
		logger().Warn("failed to refresh the ASA cache entry", "asset_id", assetID, "network", e.Network, "error", refreshErr)
	}
	return asa.Metadata{
		Network:  e.Network,
		AssetID:  assetID,
		UnitName: live.UnitName,
		Name:     live.Name,
		Decimals: live.Decimals,
		Source:   asa.SourceLive,
	}, nil
}

// refreshCachedASA stores what algod reported for an asset when its cache
// entry is missing or differs.
func (e *Engine) refreshCachedASA(assetID uint64, live cache.ASAInfo) error {
	if cached, ok := e.AsaCache.Assets[assetID]; ok && cached == live {
		return nil
	}
	return e.storeCachedASA(&ASAInfo{AssetID: assetID, UnitName: live.UnitName, Name: live.Name, Decimals: live.Decimals})
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

func (e *Engine) AddASAToCache(ctx context.Context, assetID uint64) (*ASAInfo, error) {
	info, err := e.GetASAInfoWithContext(ctx, assetID)
	if err != nil {
		return nil, err
	}

	if err := e.storeCachedASA(info); err != nil {
		return info, fmt.Errorf("added to cache but failed to save: %w", err)
	}
	return info, nil
}

// storeCachedASA writes one asset's entry to the ASA cache under the client
// data lock, reloading the file first so entries other processes wrote stay.
func (e *Engine) storeCachedASA(info *ASAInfo) error {
	return e.withClientDataLock(func() error {
		if e.DataDir != "" {
			e.AsaCache = cache.LoadASACacheFromStore(e.CacheStore, e.Network)
		}
		e.cacheASA(info)
		return e.AsaCache.SaveCacheLocked(e.Network)
	})
}

// cacheASA adds an asset to the internal cache
func (e *Engine) cacheASA(info *ASAInfo) {
	if e.AsaCache.Assets == nil {
		e.AsaCache.Assets = make(map[uint64]cache.ASAInfo)
	}
	e.AsaCache.Assets[info.AssetID] = cache.PreferBuiltin(e.Network, info.AssetID, cache.ASAInfo{
		UnitName: info.UnitName,
		Name:     info.Name,
		Decimals: info.Decimals,
	})
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
func (e *Core) ResolveASAReference(asaRef string) (uint64, error) {
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
