// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// MCP-specific result types for structured JSON responses.
// These are used only by mcpStructured() and don't need RenderText.

import (
	"fmt"
	"strconv"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/asa"
)

func jsonMarshal(v interface{}) []byte {
	return appresult.Marshal(v)
}

// --- Status ---

func (r *REPLState) mcpStatus() []byte {
	result, err := r.app().Status(r.commandContext())
	if err != nil {
		return jsonMarshal(map[string]string{"error": err.Error()})
	}
	return appresult.Marshal(appresult.StatusToMCP(appresult.StatusView{
		Network:          result.Status.Network,
		IsConnected:      result.Status.IsConnected,
		ConnectionTarget: result.Status.ConnectionTarget,
		WriteMode:        result.Status.WriteMode,
		ASACacheCount:    result.Status.ASACacheCount,
		AliasCacheCount:  result.Status.AliasCacheCount,
		SetCacheCount:    result.Status.SetCacheCount,
		SignerKeyCount:   result.Status.SignerCacheCount,
	}, result.TunnelConnected))
}

func (r *REPLState) mcpAccounts() ([]byte, error) {
	result, err := r.app().Accounts(r.commandContext())
	if err != nil {
		return nil, err
	}
	projected := make([]appresult.AccountView, len(result.Accounts))
	for i, account := range result.Accounts {
		projected[i] = appresult.AccountView{
			Address:    account.Address,
			Alias:      account.Alias,
			Source:     account.Source,
			IsSignable: account.IsSignable,
			KeyType:    account.KeyType,
		}
	}
	return appresult.Marshal(appresult.AccountsToMCP(projected)), nil
}

// --- Balance ---

func (r *REPLState) mcpBalance(args []string) ([]byte, error) {
	account, assetRef, err := r.parseMCPBalanceArgs(args)
	if err != nil {
		return nil, err
	}

	// Handle @set references
	if len(account) > 0 && account[0] == '@' {
		addresses, err := r.app().ResolveAddressList([]string{account})
		if err != nil {
			return nil, err
		}
		var results []appresult.MCPBalance
		for _, addr := range addresses {
			b, err := r.app().BalanceForAddress(r.commandContext(), addr)
			if err != nil {
				continue
			}
			results = append(results, projectMCPBalanceForAsset(r.app(), b, assetRef))
		}
		return appresult.Marshal(results), nil
	}

	// Single account
	b, err := r.app().BalanceForAddress(r.commandContext(), account)
	if err != nil {
		return nil, err
	}
	return appresult.Marshal(projectMCPBalanceForAsset(r.app(), b, assetRef)), nil
}

func (r *REPLState) parseMCPBalanceArgs(args []string) (account string, assetRef string, err error) {
	account = "@all"
	if len(args) == 0 {
		return account, "", nil
	}

	firstArg := args[0]
	if firstArg != "" && firstArg[0] != '@' && len(firstArg) != 58 && !r.app().HasAlias(firstArg) {
		return account, firstArg, nil
	}

	account = firstArg
	if len(args) >= 2 {
		assetRef = args[1]
	}
	return account, assetRef, nil
}

func projectMCPBalanceForAsset(app *apshellapp.App, result *apshellapp.BalanceDetails, assetRef string) appresult.MCPBalance {
	assets := make([]appresult.AssetBalanceView, len(result.Assets))
	for i, asset := range result.Assets {
		assets[i] = appresult.AssetBalanceView{
			AssetID:  asset.AssetID,
			Amount:   asset.Amount,
			UnitName: asset.UnitName,
			Decimals: asset.Decimals,
			IsFrozen: asset.IsFrozen,
		}
	}
	projected := appresult.BalanceToMCP(appresult.BalanceView{
		Address:     result.Address,
		Alias:       result.Alias,
		AlgoBalance: result.AlgoBalance,
		AuthAddr:    result.AuthAddr,
		MinBalance:  result.MinBalance,
		Assets:      assets,
	})
	if assetRef == "" || assetRef == "algo" || assetRef == "ALGO" {
		projected.Assets = nil
		return projected
	}

	meta, err := app.ResolveAssetMetadata(assetRef)
	if err != nil {
		return projected
	}

	filtered := projected.Assets[:0]
	for _, asset := range projected.Assets {
		if asset.AssetID == meta.AssetID {
			filtered = append(filtered, asset)
		}
	}
	projected.Assets = filtered
	if len(projected.Assets) == 0 {
		projected.Assets = []appresult.MCPAssetEntry{{
			AssetID:   meta.AssetID,
			Amount:    0,
			AmountStr: asa.FormatDisplayAmount(0, meta),
			UnitName:  meta.UnitName,
			Decimals:  meta.Decimals,
		}}
	}
	return projected
}

func (r *REPLState) mcpParticipation(args []string) ([]byte, error) {
	result, err := r.app().Participation(r.commandContext(), args)
	if err != nil {
		return nil, err
	}
	return appresult.Marshal(appresult.ParticipationToMCP(appresult.ParticipationView{
		Address:           result.Participation.Address,
		IsOnline:          result.Participation.IsOnline,
		IncentiveEligible: result.Participation.IncentiveEligible,
		VoteKey:           result.Participation.VoteKey,
		SelectionKey:      result.Participation.SelectionKey,
		StateProofKey:     result.Participation.StateProofKey,
		VoteFirstValid:    result.Participation.VoteFirstValid,
		VoteLastValid:     result.Participation.VoteLastValid,
		VoteKeyDilution:   result.Participation.VoteKeyDilution,
	}, result.IsRekeyed, result.AuthAddress)), nil
}

// --- Key Types ---

func (r *REPLState) mcpKeytypes() ([]byte, error) {
	result, err := r.app().KeyTypes(r.commandContext())
	if err != nil {
		return nil, err
	}
	return jsonMarshal(result.KeyTypes), nil
}

func (r *REPLState) mcpAliases() []byte {
	result, err := r.app().Alias(r.commandContext(), []string{"list"})
	if err != nil {
		return jsonMarshal(map[string]string{"error": err.Error()})
	}
	aliases := make([]appresult.AliasView, len(result.Aliases))
	for i, alias := range result.Aliases {
		aliases[i] = appresult.AliasView{
			Name:       alias.Name,
			Address:    alias.Address,
			IsSignable: alias.IsSignable,
			KeyType:    alias.KeyType,
		}
	}
	return appresult.Marshal(appresult.AliasesToMCP(aliases))
}

// --- Sets ---

func (r *REPLState) mcpSets() []byte {
	result, err := r.app().Sets(r.commandContext(), []string{"list"})
	if err != nil {
		return jsonMarshal(map[string]string{"error": err.Error()})
	}
	sets := make([]appresult.SetView, len(result.Sets))
	for i, set := range result.Sets {
		sets[i] = appresult.SetView{
			Name:      set.Name,
			Addresses: set.Addresses,
			Count:     set.Count,
		}
	}
	return appresult.Marshal(appresult.SetsToMCP(sets))
}

func (r *REPLState) mcpInfo(args []string) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("usage: info <asa-id>")
	}
	asaID, err := parseUint64(args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid ASA ID: %s", args[0])
	}
	result, err := r.app().ASAInfo(r.commandContext(), asaID)
	if err != nil {
		return nil, err
	}
	return appresult.Marshal(appresult.ASAInfoToMCP(appresult.ASAInfoView{
		AssetID:       result.Info.AssetID,
		Name:          result.Info.Name,
		UnitName:      result.Info.UnitName,
		Decimals:      result.Info.Decimals,
		Total:         result.Info.Total,
		URL:           result.Info.URL,
		Creator:       result.Info.Creator,
		Manager:       result.Info.Manager,
		Reserve:       result.Info.Reserve,
		Freeze:        result.Info.Freeze,
		Clawback:      result.Info.Clawback,
		DefaultFrozen: result.Info.DefaultFrozen,
	})), nil
}

// --- ASA Cache List ---

func (r *REPLState) mcpASAList() []byte {
	result, err := r.app().ASACacheList(r.commandContext())
	if err != nil {
		return jsonMarshal(map[string]string{"error": err.Error()})
	}
	projected := make([]appresult.ASAInfoView, len(result.ASAs))
	for i, info := range result.ASAs {
		projected[i] = appresult.ASAInfoView{
			AssetID:       info.AssetID,
			Name:          info.Name,
			UnitName:      info.UnitName,
			Decimals:      info.Decimals,
			Total:         info.Total,
			URL:           info.URL,
			Creator:       info.Creator,
			Manager:       info.Manager,
			Reserve:       info.Reserve,
			Freeze:        info.Freeze,
			Clawback:      info.Clawback,
			DefaultFrozen: info.DefaultFrozen,
		}
	}
	return appresult.Marshal(appresult.CachedASAsToMCP(projected))
}

func (r *REPLState) mcpHolders(args []string) ([]byte, error) {
	assetRef := "algo"
	if len(args) > 1 {
		return nil, fmt.Errorf("usage: holders [asa|algo]")
	}
	if len(args) == 1 {
		assetRef = args[0]
	}

	addresses, err := r.app().AllAddresses(r.commandContext())
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no accounts found")
	}

	isAlgo := assetRef == "" || assetRef == "algo" || assetRef == "ALGO"
	meta, _ := r.app().ResolveAssetMetadata("algo")
	if !isAlgo {
		meta, err = r.app().ResolveAssetMetadata(assetRef)
		if err != nil {
			return nil, fmt.Errorf("unknown asset '%s': %w", assetRef, err)
		}
	}
	asaID := meta.AssetID
	unitName := meta.UnitName
	decimals := meta.Decimals

	var holders []appresult.MCPHolderEntry
	var totalRaw uint64

	for _, addr := range addresses {
		b, err := r.app().BalanceForAddress(r.commandContext(), addr)
		if err != nil {
			continue
		}
		var rawBalance uint64
		if isAlgo {
			rawBalance = b.AlgoBalance
		} else {
			for _, asset := range b.Assets {
				if asset.AssetID == asaID {
					rawBalance = asset.Amount
					break
				}
			}
		}
		if rawBalance > 0 {
			holders = append(holders, appresult.HolderEntryToMCP(addr, b.Alias, rawBalance, decimals))
			totalRaw += rawBalance
		}
	}

	return appresult.Marshal(appresult.HoldersToMCP(unitName, decimals, holders, totalRaw)), nil
}

func parseUint64(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", s)
	}
	return n, nil
}
