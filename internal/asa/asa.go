// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package asa owns ASA metadata resolution and amount formatting/parsing.
package asa

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	algoutil "github.com/aplane-algo/aplane/internal/algo"
	asaregistry "github.com/aplane-algo/aplane/internal/asa/registry"
	"github.com/aplane-algo/aplane/internal/cache"
)

const (
	SourceBuiltin = "builtin"
	SourceCache   = "cache"
	SourceLive    = "live"
	SourceIDOnly  = "id_only"
)

type Metadata struct {
	Network  string
	AssetID  uint64
	UnitName string
	Name     string
	Decimals uint64
	Source   string
}

type Amount struct {
	Meta Metadata
	Raw  uint64
}

type Resolver struct {
	Network     string
	Cache       *cache.ASACache
	AlgodClient *algod.Client
}

func NewResolver(network string, asaCache *cache.ASACache, algodClient *algod.Client) Resolver {
	return Resolver{
		Network:     network,
		Cache:       asaCache,
		AlgodClient: algodClient,
	}
}

func BuiltinMetadata(network string, assetID uint64) (Metadata, bool) {
	info, ok := cache.BuiltinASAInfo(network, assetID)
	if !ok {
		return Metadata{}, false
	}
	return metadataFromInfo(network, assetID, info, SourceBuiltin), true
}

func BuiltinMetadataByRef(network, ref string) (Metadata, bool) {
	assetID, ok, err := asaregistry.ResolveReference(network, ref)
	if err != nil || !ok {
		return Metadata{}, false
	}
	return BuiltinMetadata(network, assetID)
}

func (r Resolver) ResolveID(ref string) (uint64, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, fmt.Errorf("empty asset reference")
	}
	if assetID, err := strconv.ParseUint(ref, 10, 64); err == nil {
		return assetID, nil
	}
	if r.Cache == nil {
		if assetID, ok, err := asaregistry.ResolveReference(r.Network, ref); err != nil {
			return 0, err
		} else if ok {
			return assetID, nil
		}
		return 0, fmt.Errorf("asset %q not found on %s (no ASA cache available)", ref, r.Network)
	}
	return r.Cache.ResolveASAReference(ref, r.Network)
}

func (r Resolver) ResolveMetadata(ref string) (Metadata, error) {
	assetID, err := r.ResolveID(ref)
	if err != nil {
		return Metadata{}, err
	}
	return r.MetadataByID(assetID)
}

func (r Resolver) MetadataByID(assetID uint64) (Metadata, error) {
	if r.Cache != nil {
		if info, ok := r.Cache.Assets[assetID]; ok {
			return metadataFromInfo(r.Network, assetID, info, SourceCache), nil
		}
	}
	if meta, ok := BuiltinMetadata(r.Network, assetID); ok {
		return meta, nil
	}
	if r.AlgodClient != nil && r.Cache != nil {
		info, err := r.Cache.GetASAInfo(r.AlgodClient, assetID, r.Network)
		if err != nil {
			return Metadata{}, err
		}
		return metadataFromInfo(r.Network, assetID, info, SourceLive), nil
	}
	if r.AlgodClient != nil {
		var tmp cache.ASACache
		tmp.Assets = make(map[uint64]cache.ASAInfo)
		info, err := tmp.GetASAInfo(r.AlgodClient, assetID, r.Network)
		if err != nil {
			return Metadata{}, err
		}
		return metadataFromInfo(r.Network, assetID, info, SourceLive), nil
	}
	return Metadata{
		Network: r.Network,
		AssetID: assetID,
		Source:  SourceIDOnly,
	}, nil
}

func AmountFromRaw(raw uint64, meta Metadata) Amount {
	return Amount{Meta: meta, Raw: raw}
}

func AmountFromDisplay(amount string, meta Metadata) (Amount, error) {
	raw, err := ParseDisplayAmount(amount, meta)
	if err != nil {
		return Amount{}, err
	}
	return Amount{Meta: meta, Raw: raw}, nil
}

func ParseDisplayAmount(amount string, meta Metadata) (uint64, error) {
	// SourceIDOnly means the resolver could not determine the asset's decimals
	// (no cache entry, not built in, no algod) and defaulted Decimals to 0.
	// Converting a display amount against unknown decimals would silently
	// under-send by 10^d (e.g. "5" of a 6-decimal asset becomes 5 base units),
	// so refuse: callers must resolve real metadata or pass a raw base-unit
	// amount via AmountFromRaw instead.
	if meta.Source == SourceIDOnly {
		return 0, fmt.Errorf("cannot parse display amount for asset %d: decimals are unknown (resolve asset metadata or pass a raw base-unit amount)", meta.AssetID)
	}
	return algoutil.ConvertTokenAmountToBaseUnits(strings.TrimSpace(amount), meta.Decimals)
}

func FormatDisplayAmount(raw uint64, meta Metadata) string {
	return trimDisplayAmount(FormatAmountWithDecimals(raw, meta.Decimals))
}

func DisplayRef(meta Metadata) string {
	if strings.TrimSpace(meta.UnitName) != "" {
		return meta.UnitName
	}
	return strconv.FormatUint(meta.AssetID, 10)
}

func DisplayString(a Amount) string {
	return fmt.Sprintf("%s %s", FormatDisplayAmount(a.Raw, a.Meta), DisplayRef(a.Meta))
}

func metadataFromInfo(network string, assetID uint64, info cache.ASAInfo, source string) Metadata {
	return Metadata{
		Network:  network,
		AssetID:  assetID,
		UnitName: info.UnitName,
		Name:     info.Name,
		Decimals: info.Decimals,
		Source:   source,
	}
}

func trimDisplayAmount(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if s == "" {
		return "0"
	}
	return s
}
