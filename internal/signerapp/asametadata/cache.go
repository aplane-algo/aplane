// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package asametadata owns signer-side ASA metadata lookup and cache storage.
package asametadata

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	signutil "github.com/aplane-algo/aplane/internal/signing"
)

var cacheMu sync.Mutex

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
func (s Store) MetadataByID(network string, assetID uint64, cfg *apconfig.ServerConfig, allowLive bool) (asa.Metadata, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	asaCache := s.load(network)
	resolver := asa.NewResolver(network, &asaCache, algodClientForNetwork(network, cfg, allowLive))
	meta, err := resolver.MetadataByID(assetID)
	if err != nil {
		return asa.Metadata{}, err
	}
	if meta.Source == asa.SourceIDOnly {
		return asa.Metadata{}, fmt.Errorf("asset %d on %s could not be resolved", assetID, network)
	}
	return meta, nil
}

// Formatter returns a policy formatter that uses only signer-local metadata.
func (s Store) Formatter() func(network string, assetID uint64, raw uint64) (string, bool) {
	return func(network string, assetID uint64, raw uint64) (string, bool) {
		meta, err := s.MetadataByID(network, assetID, nil, false)
		if err != nil {
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

func algodClientForNetwork(network string, cfg *apconfig.ServerConfig, allowLive bool) *algod.Client {
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
