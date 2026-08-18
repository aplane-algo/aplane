// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/asa"
)

type aliasProjection struct {
	Mode            string   `json:"mode"`
	Name            string   `json:"name,omitempty"`
	Address         string   `json:"address,omitempty"`
	PreviousAddress string   `json:"previous_address,omitempty"`
	Updated         bool     `json:"updated,omitempty"`
	Usage           []string `json:"usage,omitempty"`
}

func projectAliasResult(result *apshellapp.AliasCommandResult) interface{} {
	if result.Mode == "list" {
		aliases := make([]appresult.AliasView, len(result.Aliases))
		for i, alias := range result.Aliases {
			aliases[i] = appresult.AliasView{
				Name: alias.Name, Address: alias.Address,
				IsSignable: alias.IsSignable, KeyType: alias.KeyType,
			}
		}
		return appresult.AliasesToMCP(aliases)
	}
	projection := aliasProjection{Mode: result.Mode, Name: result.Name, Usage: result.Usage}
	switch result.Mode {
	case "show":
		if result.Alias != nil {
			projection.Address = result.Alias.Address
		}
	case "delete":
		projection.PreviousAddress = result.Removed
	case "upsert":
		if result.Added != nil {
			projection.Address = result.Added.Address
			projection.PreviousAddress = result.Added.OldAddress
			projection.Updated = result.Added.WasUpdated
		}
	}
	return projection
}

type setsProjection struct {
	Mode      string   `json:"mode"`
	Name      string   `json:"name,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Count     int      `json:"count,omitempty"`
	OldCount  int      `json:"old_count,omitempty"`
	Updated   bool     `json:"updated,omitempty"`
	Usage     []string `json:"usage,omitempty"`
}

func projectSetsResult(result *apshellapp.SetsCommandResult) interface{} {
	if result.Mode == "list" {
		sets := make([]appresult.SetView, len(result.Sets))
		for i, set := range result.Sets {
			sets[i] = appresult.SetView{Name: set.Name, Addresses: set.Addresses, Count: set.Count}
		}
		return appresult.SetsToMCP(sets)
	}
	projection := setsProjection{
		Mode: result.Mode, Name: result.SetName, Addresses: result.Addresses,
		Count: result.Count, Usage: result.Usage,
	}
	if result.Mutation != nil {
		projection.Name = result.Mutation.Name
		projection.Addresses = result.Mutation.Addresses
		projection.Count = len(result.Mutation.Addresses)
		projection.OldCount = result.Mutation.OldCount
		projection.Updated = result.Mutation.WasUpdated
	}
	return projection
}

type asaCacheProjection struct {
	Mode    string `json:"mode"`
	Network string `json:"network"`
	AssetID uint64 `json:"asset_id,omitempty"`
	Unit    string `json:"unit_name,omitempty"`
	Count   int    `json:"count,omitempty"`
}

func projectASAInfo(info apshellapp.ASAInfoDetails) appresult.MCPASAInfo {
	return appresult.ASAInfoToMCP(appresult.ASAInfoView{
		AssetID: info.AssetID, Name: info.Name, UnitName: info.UnitName,
		Decimals: info.Decimals, Total: info.Total, URL: info.URL,
		Creator: info.Creator, Manager: info.Manager, Reserve: info.Reserve,
		Freeze: info.Freeze, Clawback: info.Clawback, DefaultFrozen: info.DefaultFrozen,
	})
}

func projectASACacheResult(result *apshellapp.ASACommandResult) interface{} {
	if result.Mode == "list" {
		items := make([]appresult.ASAInfoView, len(result.ASAs))
		for i, info := range result.ASAs {
			items[i] = appresult.ASAInfoView{
				AssetID: info.AssetID, Name: info.Name, UnitName: info.UnitName, Decimals: info.Decimals,
			}
		}
		return appresult.CachedASAsToMCP(items)
	}
	projection := asaCacheProjection{
		Mode: result.Mode, Network: result.Network, AssetID: result.AssetID, Count: result.Count,
	}
	if result.Info != nil {
		projection.Unit = result.Info.UnitName
	}
	return projection
}

type networkProjection struct {
	OldNetwork string `json:"old_network"`
	Network    string `json:"network"`
}

type generatedKeyProjection struct {
	KeyType string `json:"key_type"`
	Address string `json:"address"`
}

type deletedKeyProjection struct {
	Address   string `json:"address"`
	Deleted   bool   `json:"deleted"`
	Cancelled bool   `json:"cancelled,omitempty"`
}

type connectionProjection struct {
	Connected        bool   `json:"connected"`
	Target           string `json:"target,omitempty"`
	Port             int    `json:"port,omitempty"`
	KeyCount         int    `json:"key_count,omitempty"`
	Locked           bool   `json:"locked,omitempty"`
	AlreadyConnected bool   `json:"already_connected,omitempty"`
}

type disconnectProjection struct {
	WasConnected bool `json:"was_connected"`
}

type endpointProjection struct {
	Alias        string `json:"alias"`
	Role         string `json:"role"`
	URL          string `json:"url"`
	SignerPort   int    `json:"signer_port,omitempty"`
	LocalPort    int    `json:"local_port,omitempty"`
	TokenPresent bool   `json:"token_present"`
	TokenStatus  string `json:"token_status"`
	Default      bool   `json:"default"`
}

func projectEndpointEntry(endpoint apshellapp.EndpointEntry) endpointProjection {
	return endpointProjection{
		Alias: endpoint.Alias, Role: endpoint.Role, URL: endpoint.URL,
		SignerPort: endpoint.SignerPort, LocalPort: endpoint.LocalPort,
		TokenPresent: endpoint.TokenPresent, TokenStatus: tokenStatusLabel(endpoint),
		Default: endpoint.IsDefault,
	}
}

type endpointMutationProjection struct {
	Mode            string `json:"mode"`
	Alias           string `json:"alias"`
	Role            string `json:"role,omitempty"`
	URL             string `json:"url,omitempty"`
	Port            int    `json:"port,omitempty"`
	DryRun          bool   `json:"dry_run,omitempty"`
	Created         bool   `json:"created,omitempty"`
	Updated         bool   `json:"updated,omitempty"`
	DefaultChanged  bool   `json:"default_changed,omitempty"`
	PreviousDefault string `json:"previous_default,omitempty"`
	Deleted         bool   `json:"deleted,omitempty"`
}

type endpointDiscoveryProjection struct {
	Endpoints      []endpointDiscoveryEntry `json:"endpoints"`
	PublicKeyCount int                      `json:"public_key_count"`
}

type endpointDiscoveryEntry struct {
	Alias   string                 `json:"alias"`
	Keys    []endpointDiscoveryKey `json:"keys,omitempty"`
	Skipped bool                   `json:"skipped,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

type endpointDiscoveryKey struct {
	PublicKey    string `json:"public_key"`
	ComponentKey string `json:"component_key"`
	KeyType      string `json:"key_type"`
}

type pluginCommandProjection struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Author      string   `json:"author,omitempty"`
	Networks    []string `json:"networks,omitempty"`
	Commands    []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Usage       string `json:"usage,omitempty"`
	} `json:"commands"`
}

type pluginsProjection struct {
	Mode    string                    `json:"mode"`
	Plugin  *pluginCommandProjection  `json:"plugin,omitempty"`
	Plugins []pluginCommandProjection `json:"plugins,omitempty"`
}

func projectPluginsResult(result *apshellapp.PluginsCommandResult) pluginsProjection {
	projection := pluginsProjection{Mode: result.Mode}
	project := func(plugin apshellapp.PluginCommandSummary) pluginCommandProjection {
		item := pluginCommandProjection{
			Name: plugin.Name, Version: plugin.Version, Description: plugin.Description,
			Author: plugin.Author, Networks: plugin.Networks,
		}
		item.Commands = make([]struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Usage       string `json:"usage,omitempty"`
		}, len(plugin.Commands))
		for i, cmd := range plugin.Commands {
			item.Commands[i].Name = cmd.Name
			item.Commands[i].Description = cmd.Description
			item.Commands[i].Usage = cmd.Usage
		}
		return item
	}
	if result.Plugin != nil {
		item := project(*result.Plugin)
		projection.Plugin = &item
	}
	projection.Plugins = make([]pluginCommandProjection, len(result.Plugins))
	for i, plugin := range result.Plugins {
		projection.Plugins[i] = project(plugin)
	}
	return projection
}

func projectMCPBalanceForAsset(app *apshellapp.App, result *apshellapp.BalanceDetails, assetRef string) appresult.MCPBalance {
	assets := make([]appresult.AssetBalanceView, len(result.Assets))
	for i, asset := range result.Assets {
		assets[i] = appresult.AssetBalanceView{
			AssetID: asset.AssetID, Amount: asset.Amount, UnitName: asset.UnitName,
			Decimals: asset.Decimals, IsFrozen: asset.IsFrozen,
		}
	}
	projected := appresult.BalanceToMCP(appresult.BalanceView{
		Address: result.Address, Alias: result.Alias, AlgoBalance: result.AlgoBalance,
		AuthAddr: result.AuthAddr, MinBalance: result.MinBalance, Assets: assets,
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
			AssetID: meta.AssetID, Amount: 0, AmountStr: asa.FormatDisplayAmount(0, meta),
			UnitName: meta.UnitName, Decimals: meta.Decimals,
		}}
	}
	return projected
}

func (r *REPLState) projectHolders(result *apshellapp.HoldersCommandResult) (interface{}, error) {
	isAlgo := result.AssetRef == "" || result.AssetRef == "algo" || result.AssetRef == "ALGO"
	meta, _ := r.app().ResolveAssetMetadata("algo")
	if !isAlgo {
		var err error
		meta, err = r.app().ResolveAssetMetadata(result.AssetRef)
		if err != nil {
			return nil, fmt.Errorf("unknown asset '%s': %w", result.AssetRef, err)
		}
	}
	entries := make([]appresult.MCPHolderEntry, 0, len(result.Balances))
	var totalRaw uint64
	for _, balance := range result.Balances {
		var raw uint64
		if isAlgo {
			raw = balance.AlgoBalance
		} else {
			for _, asset := range balance.Assets {
				if asset.AssetID == meta.AssetID {
					raw = asset.Amount
					break
				}
			}
		}
		if raw == 0 {
			continue
		}
		entries = append(entries, appresult.HolderEntryToMCP(balance.Address, balance.Alias, raw, meta.Decimals))
		totalRaw += raw
	}
	return appresult.HoldersToMCP(meta.UnitName, meta.Decimals, entries, totalRaw), nil
}

type sendProjection struct {
	Mode         string               `json:"mode"`
	Amount       string               `json:"amount"`
	TxIDs        []string             `json:"tx_ids,omitempty"`
	Confirmed    bool                 `json:"confirmed"`
	Simulated    bool                 `json:"simulated"`
	SuccessCount int                  `json:"success_count,omitempty"`
	FailureCount int                  `json:"failure_count,omitempty"`
	Items        []sendItemProjection `json:"items,omitempty"`
}

type sendItemProjection struct {
	From      string `json:"from"`
	To        string `json:"to"`
	TxID      string `json:"tx_id,omitempty"`
	Confirmed bool   `json:"confirmed"`
	Error     string `json:"error,omitempty"`
}

func projectSendResult(result *apshellapp.SendExecutionResult, simulated bool) sendProjection {
	projection := sendProjection{Mode: string(result.Mode), Amount: asa.DisplayString(result.Amount), Simulated: simulated}
	if result.NonAtomic != nil {
		projection.SuccessCount = result.NonAtomic.SuccessCount
		projection.FailureCount = result.NonAtomic.FailureCount
		projection.Items = make([]sendItemProjection, len(result.NonAtomic.Items))
		for i, item := range result.NonAtomic.Items {
			projection.Items[i] = sendItemProjection{
				From: item.From, To: item.To, TxID: item.TxID, Confirmed: item.Confirmed, Error: item.Error,
			}
			if item.TxID != "" {
				projection.TxIDs = append(projection.TxIDs, item.TxID)
			}
			projection.Confirmed = projection.Confirmed || item.Confirmed
		}
	}
	if result.Atomic != nil {
		projection.TxIDs = append([]string(nil), result.Atomic.TxIDs...)
		projection.Confirmed = result.Atomic.Confirmed
	}
	return projection
}

type sweepProjection struct {
	Asset        string                `json:"asset"`
	Destination  string                `json:"destination"`
	Simulated    bool                  `json:"simulated"`
	SuccessCount int                   `json:"success_count"`
	FailureCount int                   `json:"failure_count"`
	LastTxID     string                `json:"last_tx_id,omitempty"`
	Items        []sweepItemProjection `json:"items"`
}

type sweepItemProjection struct {
	From          string `json:"from"`
	TxID          string `json:"tx_id,omitempty"`
	Confirmed     bool   `json:"confirmed"`
	SkippedReason string `json:"skipped_reason,omitempty"`
	Error         string `json:"error,omitempty"`
}

func projectSweepResult(result *apshellapp.SweepCommandResult, simulated bool) sweepProjection {
	projection := sweepProjection{
		Asset: result.Asset.UnitName, Destination: result.ToAddress, Simulated: simulated,
		SuccessCount: result.SuccessCount, FailureCount: result.FailureCount,
		LastTxID: result.LastTxID, Items: make([]sweepItemProjection, len(result.Items)),
	}
	for i, item := range result.Items {
		projection.Items[i] = sweepItemProjection{
			From: item.From, TxID: item.TxID, Confirmed: item.Confirmed,
			SkippedReason: item.SkippedReason, Error: item.Error,
		}
	}
	return projection
}

type signFileProjection struct {
	TransactionCount int      `json:"transaction_count"`
	TxIDs            []string `json:"tx_ids,omitempty"`
	Confirmed        bool     `json:"confirmed"`
	Simulated        bool     `json:"simulated"`
}

type optInProjection struct {
	Account   string `json:"account"`
	AssetID   uint64 `json:"asset_id"`
	TxID      string `json:"tx_id,omitempty"`
	Confirmed bool   `json:"confirmed"`
	Simulated bool   `json:"simulated"`
}

type optOutProjection struct {
	Account   string `json:"account"`
	AssetID   uint64 `json:"asset_id"`
	CloseTo   string `json:"close_to,omitempty"`
	TxID      string `json:"tx_id,omitempty"`
	Confirmed bool   `json:"confirmed"`
	Simulated bool   `json:"simulated"`
}

type keyRegProjection struct {
	Account   string `json:"account"`
	Mode      string `json:"mode"`
	TxID      string `json:"tx_id,omitempty"`
	Confirmed bool   `json:"confirmed"`
	Simulated bool   `json:"simulated"`
}

type validateProjection struct {
	SuccessCount int                      `json:"success_count"`
	FailureCount int                      `json:"failure_count"`
	Simulated    bool                     `json:"simulated"`
	Items        []validateItemProjection `json:"items"`
}

type validateItemProjection struct {
	Address   string `json:"address"`
	TxID      string `json:"tx_id,omitempty"`
	Confirmed bool   `json:"confirmed"`
	Error     string `json:"error,omitempty"`
}

type closeProjection struct {
	From      string `json:"from"`
	CloseTo   string `json:"close_to"`
	TxID      string `json:"tx_id,omitempty"`
	Confirmed bool   `json:"confirmed"`
	Simulated bool   `json:"simulated"`
}

type rekeyProjection struct {
	Mode      string                  `json:"mode"`
	From      string                  `json:"from,omitempty"`
	To        string                  `json:"to,omitempty"`
	TxID      string                  `json:"tx_id,omitempty"`
	Confirmed bool                    `json:"confirmed,omitempty"`
	Simulated bool                    `json:"simulated,omitempty"`
	Entries   []rekeyEntryProjection  `json:"entries,omitempty"`
	Refreshed []authRefreshProjection `json:"refreshed,omitempty"`
}

type rekeyEntryProjection struct {
	Address     string `json:"address"`
	AuthAddress string `json:"auth_address"`
}

type authRefreshProjection struct {
	Address     string `json:"address"`
	AuthAddress string `json:"auth_address,omitempty"`
	IsRekeyed   bool   `json:"is_rekeyed"`
}
