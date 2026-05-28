// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"

	"github.com/aplane-algo/aplane/internal/engine"
)

func asaInfoDetailsFromEngine(info *engine.ASAInfo) *ASAInfoDetails {
	if info == nil {
		return nil
	}
	return &ASAInfoDetails{
		AssetID:       info.AssetID,
		UnitName:      info.UnitName,
		Name:          info.Name,
		Decimals:      info.Decimals,
		Total:         info.Total,
		Creator:       info.Creator,
		Manager:       info.Manager,
		Reserve:       info.Reserve,
		Freeze:        info.Freeze,
		Clawback:      info.Clawback,
		DefaultFrozen: info.DefaultFrozen,
		URL:           info.URL,
	}
}

func asaInfoDetailsListFromEngine(items []engine.ASAInfo) []ASAInfoDetails {
	result := make([]ASAInfoDetails, len(items))
	for i := range items {
		result[i] = *asaInfoDetailsFromEngine(&items[i])
	}
	return result
}

// ASAInfo returns metadata for a specific ASA.
func (a *App) ASAInfo(ctx context.Context, assetID uint64) (*ASAInfoCommandResult, error) {
	info, err := a.eng.GetASAInfoWithContext(ctx, assetID)
	if err != nil {
		return nil, err
	}
	return &ASAInfoCommandResult{Info: *asaInfoDetailsFromEngine(info)}, nil
}

// ASACacheList returns the current cached ASA metadata set.
func (a *App) ASACacheList(_ context.Context) (*ASACommandResult, error) {
	return &ASACommandResult{
		Mode:    "list",
		Network: a.Network(),
		ASAs:    asaInfoDetailsListFromEngine(a.eng.ListCachedASAs()),
	}, nil
}

// ASACacheAdd resolves and stores one ASA in the current network cache.
func (a *App) ASACacheAdd(ctx context.Context, assetID uint64) (*ASACommandResult, error) {
	info, err := a.eng.AddASAToCacheWithContext(ctx, assetID)
	if err != nil {
		return nil, err
	}
	return &ASACommandResult{
		Mode:    "add",
		Network: a.Network(),
		AssetID: assetID,
		Info:    asaInfoDetailsFromEngine(info),
	}, nil
}

// ASACacheRemove removes one ASA from the current network cache.
func (a *App) ASACacheRemove(_ context.Context, assetID uint64) (*ASACommandResult, error) {
	if err := a.eng.RemoveASAFromCache(assetID); err != nil {
		return nil, err
	}
	return &ASACommandResult{
		Mode:    "remove",
		Network: a.Network(),
		AssetID: assetID,
	}, nil
}

// ASACacheClear clears the current network cache.
func (a *App) ASACacheClear(_ context.Context) (*ASACommandResult, error) {
	count, err := a.eng.ClearASACache()
	return &ASACommandResult{
		Mode:    "clear",
		Network: a.Network(),
		Count:   count,
	}, err
}
