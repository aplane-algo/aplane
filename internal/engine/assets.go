// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
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
// builds. It does not trust the ASA cache: what the transaction needs is read
// from algod, and the asset's cache entry is refreshed with what was read.
type TransactionASAResolver struct {
	ctx    context.Context
	eng    *Engine
	idOnly bool
}

// ASAResolverForTransaction returns the asset resolver for a command that
// converts an amount of the asset (send, sweep): an asset that is not built
// in is read from algod for its decimals. Display paths keep using
// ASAResolver.
func (e *Engine) ASAResolverForTransaction(ctx context.Context) TransactionASAResolver {
	return TransactionASAResolver{ctx: ctx, eng: e}
}

// ASAIDResolverForTransaction returns the asset resolver for a command that
// needs only the asset's ID (opt-in, opt-out, app-call asset references). It
// reads algod only to confirm a name that came from the cache. For an ID or a
// registry alias the metadata is the ID with cached names for display, and its
// decimals are unknown (SourceIDOnly) unless the asset is built in.
func (e *Engine) ASAIDResolverForTransaction(ctx context.Context) TransactionASAResolver {
	return TransactionASAResolver{ctx: ctx, eng: e, idOnly: true}
}

// ResolveMetadata resolves ref for a transaction. A built-in asset is
// answered from the reviewed table without a read. A name that only the
// cache gave must still be the asset's name on the network; when it is not,
// the corrected cache entry is kept and the command is refused, because the
// name stood for another asset.
func (r TransactionASAResolver) ResolveMetadata(ref string) (asa.Metadata, error) {
	e := r.eng
	ref = strings.TrimSpace(ref)
	assetID, match, err := e.ASAResolver().MatchID(ref)
	if err != nil {
		return asa.Metadata{}, err
	}
	byCachedName := match == cache.ASARefByCachedName
	// The table answers for a built-in asset unless only a cached name led
	// to it. The cache keeps built-in entries as the table has them, so that
	// should not happen; if it does, the name is confirmed like any other.
	if meta, ok := asa.BuiltinMetadata(e.Network, assetID); ok && !byCachedName {
		return meta, nil
	}
	if r.idOnly && !byCachedName {
		meta := asa.Metadata{Network: e.Network, AssetID: assetID, Source: asa.SourceIDOnly}
		if cached, ok := e.AsaCache.Assets[assetID]; ok {
			meta.UnitName, meta.Name = cached.UnitName, cached.Name
		}
		return meta, nil
	}

	live, err := r.readASA(assetID)
	if err != nil {
		if r.idOnly {
			return asa.Metadata{}, fmt.Errorf("cannot confirm that %q still names asset %d on %s: %w. Use the asset ID", ref, assetID, e.Network, err)
		}
		return asa.Metadata{}, err
	}
	refreshErr := e.refreshCachedASA(assetID, live)
	if byCachedName && !live.MatchesReference(ref) {
		corrected := "the cache entry has been corrected"
		if refreshErr != nil {
			corrected = fmt.Sprintf("correcting the cache entry failed: %v", refreshErr)
		}
		return asa.Metadata{}, fmt.Errorf("the cached name %q no longer matches asset %d on %s, which is now %q (unit %q); %s. Name the asset by its ID or its current name",
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

// readASA reads an asset's parameters from algod.
func (r TransactionASAResolver) readASA(assetID uint64) (cache.ASAInfo, error) {
	if r.eng.AlgodClient == nil {
		return cache.ASAInfo{}, ErrNoAlgodClient
	}
	params, err := cache.FetchASAParams(r.ctx, r.eng.AlgodClient, assetID)
	if err != nil {
		return cache.ASAInfo{}, fmt.Errorf("failed to get asset %d: %w", assetID, err)
	}
	return cache.ASAInfoFromParams(params), nil
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
