// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cmdspec"
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
		// A set with no accounts is an error, as for every command over a
		// set, in the shell and through MCP alike.
		addresses, err := cmdspec.ResolveAddressList([]string{account}, a.eng.NewAddressResolver())
		if err != nil {
			return nil, err
		}
		if assetRef == "" {
			assetRef = "algo"
		}
		asset, err := a.resolveShownAsset(assetRef)
		if err != nil {
			return nil, err
		}
		balances := make([]*BalanceDetails, 0, len(addresses))
		var failures []engine.AccountQueryFailure
		for _, address := range addresses {
			balanceResult, balanceErr := a.eng.GetBalance(ctx, address)
			if balanceErr != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
				failures = append(failures, engine.AccountQueryFailure{Address: address, Alias: a.eng.GetAliasForAddress(address), Err: balanceErr})
				continue
			}
			balances = append(balances, balanceDetailsFromEngine(balanceResult))
		}
		if len(failures) == len(addresses) {
			return nil, engine.NoAccountQueriedError(failures)
		}
		return &BalanceCommandResult{
			Mode:           BalanceModeMulti,
			Asset:          asset,
			AssetSpecified: assetSpecified,
			Addresses:      addresses,
			Balances:       balances,
			Warnings:       a.balanceQueryWarnings(failures),
		}, nil
	}

	mode := BalanceModeSingleFull
	var asset asa.Metadata
	if assetSpecified {
		mode = BalanceModeSingleAsset
		var err error
		if asset, err = a.resolveShownAsset(assetRef); err != nil {
			return nil, err
		}
	}

	balanceResult, err := a.eng.GetBalance(ctx, account)
	if err != nil {
		return nil, err
	}

	return &BalanceCommandResult{
		Mode:           mode,
		Asset:          asset,
		AssetSpecified: assetSpecified,
		Single:         balanceDetailsFromEngine(balanceResult),
	}, nil
}

// resolveShownAsset resolves the asset a balance or holders command shows.
// ALGO is named in any case; the shell shows it, and matches holdings, by
// the result's AssetID alone.
func (a *App) resolveShownAsset(ref string) (asa.Metadata, error) {
	meta, err := a.ResolveAssetMetadata(ref)
	if err != nil {
		return asa.Metadata{}, fmt.Errorf("unknown asset '%s': %w", ref, err)
	}
	return meta, nil
}

// balanceQueryWarnings are the failed queries of a read of several accounts,
// one balance_query_failed warning for each account, naming it and the error,
// so that the accounts shown and their total are known to leave it out.
func (a *App) balanceQueryWarnings(failures []engine.AccountQueryFailure) []Warning {
	var warnings []Warning
	for _, failure := range failures {
		warnings = append(warnings, Warning{
			Code:    "balance_query_failed",
			Message: fmt.Sprintf("could not query %s: %v", failure.Label(), failure.Err),
		})
	}
	return warnings
}
