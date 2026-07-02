// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Shared helpers for plugin transaction submission.

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// PluginSubmitResult is the engine-owned result for plugin transaction submission.
type PluginSubmitResult struct {
	TxIDs  []string
	Output string
}

func pluginAppCallInfo(txn types.Transaction) *signerapi.AppCallInfo {
	if txn.Type != types.ApplicationCallTx {
		return nil
	}
	return &signerapi.AppCallInfo{Mode: "raw"}
}

// decodeGroupSignResponse validates a group-sign response against the request
// count and decodes each signed transaction. A truncated, padded, or partially
// empty response is rejected so a malformed signer reply can never submit an
// incomplete group.
func decodeGroupSignResponse(signed []string, want int) ([][]byte, error) {
	if len(signed) != want {
		return nil, fmt.Errorf("signer returned %d signed transaction(s), want %d", len(signed), want)
	}
	decoded := make([][]byte, len(signed))
	for i, hexStr := range signed {
		if hexStr == "" {
			return nil, fmt.Errorf("signer returned no signature for position %d", i+1)
		}
		signedBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
		}
		decoded[i] = signedBytes
	}
	return decoded, nil
}

// BuildPluginContext constructs a jsonrpc.Context from the engine's caches.
// This provides plugins with account, asset, and address information.
func (e *Engine) BuildPluginContext() (jsonrpc.Context, error) {
	assets := buildPluginAssetContext(e.AsaCache.Assets)

	addressMap := make(map[string]string)
	for alias, address := range e.AliasCache.Aliases {
		addressMap[alias] = address
	}

	if err := e.EnsureSignerCache(context.Background()); err != nil {
		return jsonrpc.Context{}, err
	}
	accounts := e.signerCacheAddresses()

	return jsonrpc.Context{
		Network:    e.Network,
		Accounts:   accounts,
		Assets:     assets,
		AddressMap: addressMap,
	}, nil
}

func buildPluginAssetContext(cacheAssets map[uint64]cache.ASAInfo) []jsonrpc.ContextAsset {
	assetIDs := make([]uint64, 0, len(cacheAssets))
	for assetID := range cacheAssets {
		assetIDs = append(assetIDs, assetID)
	}
	sort.Slice(assetIDs, func(i, j int) bool { return assetIDs[i] < assetIDs[j] })

	assets := make([]jsonrpc.ContextAsset, 0, len(assetIDs))
	for _, assetID := range assetIDs {
		asaInfo := cacheAssets[assetID]
		assets = append(assets, jsonrpc.ContextAsset{
			AssetID:  assetID,
			Name:     asaInfo.Name,
			UnitName: asaInfo.UnitName,
			Decimals: asaInfo.Decimals,
		})
	}

	return assets
}
