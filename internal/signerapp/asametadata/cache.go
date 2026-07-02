// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package asametadata owns signer-side ASA metadata lookup and cache storage.
package asametadata

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	signutil "github.com/aplane-algo/aplane/internal/signing"
)

var cacheMu sync.Mutex
var liveLookups = newLiveLookupGroup()

const liveLookupTimeout = 5 * time.Second

// Store owns signer-wide ASA metadata for policy editing and rendering.
type Store struct {
	cacheStore *cache.Store
}

// NewStore returns the signer-wide ASA metadata store rooted in the signer data directory.
func NewStore(dataDir string) Store {
	return Store{cacheStore: cache.NewStoreForCacheDir(filepath.Join(dataDir, "cache"))}
}

// MetadataByID resolves signer-side metadata for an ASA. When allowLive is
// true, a cold cache can be filled from the configured algod endpoint.
func (s Store) MetadataByID(network string, assetID uint64, cfg *serverconfig.ServerConfig, allowLive bool) (asa.Metadata, error) {
	return s.MetadataByIDWithContext(context.Background(), network, assetID, cfg, allowLive)
}

// MetadataByIDWithContext is MetadataByID with a caller-supplied context for
// live algod resolution. Cache reads and writes are serialized; live network
// fetches happen outside cacheMu and are coalesced per network/asset.
func (s Store) MetadataByIDWithContext(ctx context.Context, network string, assetID uint64, cfg *serverconfig.ServerConfig, allowLive bool) (asa.Metadata, error) {
	if meta, ok := s.cachedMetadataByID(network, assetID); ok {
		return meta, nil
	}
	if !allowLive {
		return asa.Metadata{}, fmt.Errorf("asset %d on %s could not be resolved", assetID, network)
	}
	client := algodClientForNetwork(network, cfg, allowLive)
	if client == nil {
		return asa.Metadata{}, fmt.Errorf("asset %d on %s could not be resolved", assetID, network)
	}

	ctx, cancel := context.WithTimeout(ctx, liveLookupTimeout)
	defer cancel()

	key := liveLookupKey{network: network, assetID: assetID}
	return liveLookups.do(ctx, key, func() (asa.Metadata, error) {
		if meta, ok := s.cachedMetadataByID(network, assetID); ok {
			return meta, nil
		}
		return s.fetchAndCacheMetadata(ctx, network, assetID, client)
	})
}

func (s Store) cachedMetadataByID(network string, assetID uint64) (asa.Metadata, bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	asaCache := s.load(network)
	if info, ok := asaCache.Assets[assetID]; ok {
		return metadataFromCacheInfo(network, assetID, info), true
	}
	return asa.Metadata{}, false
}

func (s Store) fetchAndCacheMetadata(ctx context.Context, network string, assetID uint64, client *algod.Client) (asa.Metadata, error) {
	assetInfo, err := client.GetAssetByID(assetID).Do(ctx)
	if err != nil {
		return asa.Metadata{}, fmt.Errorf("failed to get asset info for ASA %d on %s: %w", assetID, network, err)
	}
	info := cache.ASAInfo{
		Name:     assetInfo.Params.Name,
		UnitName: assetInfo.Params.UnitName,
		Decimals: assetInfo.Params.Decimals,
	}

	cacheMu.Lock()
	asaCache := s.load(network)
	asaCache.Assets[assetID] = info
	_ = asaCache.SaveCache(network)
	cacheMu.Unlock()
	return metadataFromInfo(network, assetID, info, asa.SourceLive), nil
}

// Formatter returns a policy formatter that uses only signer-local metadata.
func (s Store) Formatter() func(network string, assetID uint64, raw uint64) (string, bool) {
	return func(network string, assetID uint64, raw uint64) (string, bool) {
		meta, ok := s.cachedMetadataByID(network, assetID)
		if !ok {
			return "", false
		}
		display := asa.DisplayString(asa.AmountFromRaw(raw, meta))
		return fmt.Sprintf("%s (ASA %d)", display, assetID), true
	}
}

// SearchLocal searches only signer-local metadata for a network. It never
// queries algod, so symbol lookup remains a cache convenience rather than an
// authoritative network lookup.
func (s Store) SearchLocal(network, query string) ([]asa.Metadata, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}

	cacheMu.Lock()
	defer cacheMu.Unlock()

	asaCache := s.load(network)
	var out []asa.Metadata
	for assetID, info := range asaCache.Assets {
		if strings.EqualFold(info.UnitName, query) {
			out = append(out, asa.Metadata{
				Network:  network,
				AssetID:  assetID,
				UnitName: info.UnitName,
				Name:     info.Name,
				Decimals: info.Decimals,
				Source:   asa.SourceCache,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AssetID < out[j].AssetID })
	return out, nil
}

// SaveLocalMetadata stores signer-local metadata for a single ASA.
func (s Store) SaveLocalMetadata(network string, meta asa.Metadata) error {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	asaCache := s.load(network)
	asaCache.Assets[meta.AssetID] = cache.ASAInfo{
		Name:     meta.Name,
		UnitName: meta.UnitName,
		Decimals: meta.Decimals,
	}
	return asaCache.SaveCache(network)
}

func (s Store) load(network string) cache.ASACache {
	return cache.LoadASACacheFromStore(s.cacheStore, network)
}

func metadataFromCacheInfo(network string, assetID uint64, info cache.ASAInfo) asa.Metadata {
	return metadataFromInfo(network, assetID, info, asa.SourceCache)
}

func metadataFromInfo(network string, assetID uint64, info cache.ASAInfo, source string) asa.Metadata {
	return asa.Metadata{
		Network:  network,
		AssetID:  assetID,
		UnitName: info.UnitName,
		Name:     info.Name,
		Decimals: info.Decimals,
		Source:   source,
	}
}

func algodClientForNetwork(network string, cfg *serverconfig.ServerConfig, allowLive bool) *algod.Client {
	if !allowLive || cfg == nil {
		return nil
	}
	algodCfg, err := cfg.GetAlgodConfig(network)
	if err != nil || algodCfg == nil {
		return nil
	}
	client, err := signutil.CreateAlgodClient(algodCfg.Server, algodCfg.Token)
	if err != nil {
		return nil
	}
	return client
}

type liveLookupKey struct {
	network string
	assetID uint64
}

type liveLookupCall struct {
	done chan struct{}
	meta asa.Metadata
	err  error
}

type liveLookupGroup struct {
	mu    sync.Mutex
	calls map[liveLookupKey]*liveLookupCall
}

func newLiveLookupGroup() *liveLookupGroup {
	return &liveLookupGroup{calls: make(map[liveLookupKey]*liveLookupCall)}
}

func (g *liveLookupGroup) do(ctx context.Context, key liveLookupKey, fn func() (asa.Metadata, error)) (asa.Metadata, error) {
	g.mu.Lock()
	if call := g.calls[key]; call != nil {
		g.mu.Unlock()
		select {
		case <-call.done:
			return call.meta, call.err
		case <-ctx.Done():
			return asa.Metadata{}, ctx.Err()
		}
	}
	call := &liveLookupCall{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	call.meta, call.err = fn()

	g.mu.Lock()
	delete(g.calls, key)
	close(call.done)
	g.mu.Unlock()
	return call.meta, call.err
}
