// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/engine"
)

// BalanceRequest requests balance information for one account or a set.
type BalanceRequest struct {
	Args []string
}

func balanceDetailsFromEngine(result *engine.BalanceResult) *BalanceDetails {
	if result == nil {
		return nil
	}
	assets := make([]AssetHolding, len(result.Assets))
	for i, asset := range result.Assets {
		assets[i] = AssetHolding{
			AssetID:   asset.AssetID,
			Amount:    asset.Amount,
			UnitName:  asset.UnitName,
			Decimals:  asset.Decimals,
			IsFrozen:  asset.IsFrozen,
			IsOptedIn: asset.IsOptedIn,
		}
	}
	return &BalanceDetails{
		Address:     result.Address,
		Alias:       result.Alias,
		AlgoBalance: result.AlgoBalance,
		Assets:      assets,
		AuthAddr:    result.AuthAddr,
		MinBalance:  result.MinBalance,
	}
}

// Balance resolves command semantics for the balance command while leaving
// presentation decisions to the shell layer.
func (a *App) Balance(ctx context.Context, req BalanceRequest) (*BalanceCommandResult, error) {
	if len(req.Args) > 2 {
		return nil, fmt.Errorf("usage: balance [account|@all|@signers|@set] [asa|algo]")
	}

	account := "@all"
	assetRef := ""
	assetSpecified := false

	if len(req.Args) >= 1 {
		firstArg := req.Args[0]
		if firstArg != "" && firstArg[0] != '@' && len(firstArg) != 58 && !a.eng.HasAlias(firstArg) {
			assetRef = firstArg
			assetSpecified = true
		} else {
			account = firstArg
			if len(req.Args) == 2 {
				assetRef = req.Args[1]
				assetSpecified = true
			}
		}
	}

	if len(account) > 0 && account[0] == '@' {
		resolver := a.eng.NewAddressResolver()
		addresses, err := resolver.ResolveList([]string{account})
		if err != nil {
			return nil, err
		}
		if assetRef == "" {
			assetRef = "algo"
		}
		balances := make([]*BalanceDetails, 0, len(addresses))
		for _, address := range addresses {
			balanceResult, balanceErr := a.eng.GetBalance(ctx, address)
			if balanceErr != nil {
				continue
			}
			balances = append(balances, balanceDetailsFromEngine(balanceResult))
		}
		return &BalanceCommandResult{
			Mode:           BalanceModeMulti,
			AssetRef:       assetRef,
			AssetSpecified: assetSpecified,
			Addresses:      addresses,
			Balances:       balances,
		}, nil
	}

	balanceResult, err := a.eng.GetBalance(ctx, account)
	if err != nil {
		return nil, err
	}
	result := balanceDetailsFromEngine(balanceResult)

	mode := BalanceModeSingleFull
	if assetSpecified {
		mode = BalanceModeSingleAsset
	}

	return &BalanceCommandResult{
		Mode:           mode,
		AssetRef:       assetRef,
		AssetSpecified: assetSpecified,
		Single:         result,
	}, nil
}
