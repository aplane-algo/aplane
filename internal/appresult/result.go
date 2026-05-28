// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appresult

import (
	"encoding/json"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// KeyInfo is the canonical structured key view for app-layer results.
type KeyInfo struct {
	Address                  string
	KeyType                  string
	TemplateProvenanceStatus string
	TemplateProvenanceNote   string
}

// Keys is the canonical structured result for signer-visible keys.
type Keys struct {
	Keys []KeyInfo
}

// Toggle is the canonical structured result for shell mode toggles.
type Toggle struct {
	Name    string
	Enabled bool
	Changed bool
}

// MCPStatus is the structured MCP projection for engine status.
type MCPStatus struct {
	Network          string `json:"network"`
	SignerConnected  bool   `json:"signer_connected"`
	ConnectionTarget string `json:"connection_target,omitempty"`
	SSHTunnel        bool   `json:"ssh_tunnel"`
	WriteMode        bool   `json:"write_mode"`
	ASACacheCount    int    `json:"asa_cache_count"`
	AliasCacheCount  int    `json:"alias_cache_count"`
	SetCacheCount    int    `json:"set_cache_count"`
	SignerKeyCount   int    `json:"signer_key_count"`
}

// MCPBalance is the structured MCP projection for a balance result.
type MCPBalance struct {
	Address        string          `json:"address"`
	Alias          string          `json:"alias,omitempty"`
	AlgoBalance    uint64          `json:"algo_balance"`
	AlgoBalanceStr string          `json:"algo_balance_display"`
	AuthAddr       string          `json:"auth_addr,omitempty"`
	MinBalance     uint64          `json:"min_balance"`
	Assets         []MCPAssetEntry `json:"assets,omitempty"`
}

// MCPAssetEntry is the structured MCP projection for an ASA balance entry.
type MCPAssetEntry struct {
	AssetID   uint64 `json:"asset_id"`
	Amount    uint64 `json:"amount"`
	AmountStr string `json:"amount_display"`
	UnitName  string `json:"unit_name"`
	Decimals  uint64 `json:"decimals"`
	IsFrozen  bool   `json:"is_frozen,omitempty"`
}

// MCPAccount is the structured MCP projection for account listings.
type MCPAccount struct {
	Address    string `json:"address"`
	Alias      string `json:"alias,omitempty"`
	Source     string `json:"source"`
	IsSignable bool   `json:"is_signable"`
	KeyType    string `json:"key_type,omitempty"`
}

// MCPAlias is the structured MCP projection for alias listings.
type MCPAlias struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	IsSignable bool   `json:"is_signable"`
	KeyType    string `json:"key_type,omitempty"`
}

// MCPSet is the structured MCP projection for set listings.
type MCPSet struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Count     int      `json:"count"`
}

// MCPParticipation is the structured MCP projection for participation status.
type MCPParticipation struct {
	Address           string `json:"address"`
	IsOnline          bool   `json:"is_online"`
	IncentiveEligible bool   `json:"incentive_eligible"`
	VoteKey           string `json:"vote_key,omitempty"`
	SelectionKey      string `json:"selection_key,omitempty"`
	StateProofKey     string `json:"state_proof_key,omitempty"`
	VoteFirstValid    uint64 `json:"vote_first_valid,omitempty"`
	VoteLastValid     uint64 `json:"vote_last_valid,omitempty"`
	VoteKeyDilution   uint64 `json:"vote_key_dilution,omitempty"`
	IsRekeyed         bool   `json:"is_rekeyed,omitempty"`
	AuthAddr          string `json:"auth_addr,omitempty"`
}

// MCPASAInfo is the structured MCP projection for ASA metadata.
type MCPASAInfo struct {
	AssetID       uint64 `json:"asset_id"`
	Name          string `json:"name"`
	UnitName      string `json:"unit_name"`
	Decimals      uint64 `json:"decimals"`
	Total         uint64 `json:"total"`
	URL           string `json:"url,omitempty"`
	Creator       string `json:"creator,omitempty"`
	Manager       string `json:"manager,omitempty"`
	Reserve       string `json:"reserve,omitempty"`
	Freeze        string `json:"freeze,omitempty"`
	Clawback      string `json:"clawback,omitempty"`
	DefaultFrozen bool   `json:"default_frozen,omitempty"`
}

// MCPASACacheEntry is the structured MCP projection for cached ASA entries.
type MCPASACacheEntry struct {
	AssetID  uint64 `json:"asset_id"`
	Name     string `json:"name"`
	UnitName string `json:"unit_name"`
	Decimals uint64 `json:"decimals"`
}

// MCPHolderEntry is the structured MCP projection for a single holder balance.
type MCPHolderEntry struct {
	Address    string `json:"address"`
	Alias      string `json:"alias,omitempty"`
	Balance    uint64 `json:"balance"`
	BalanceStr string `json:"balance_display"`
}

// MCPHolders is the structured MCP projection for a holder listing.
type MCPHolders struct {
	Asset    string           `json:"asset"`
	Decimals uint64           `json:"decimals"`
	Holders  []MCPHolderEntry `json:"holders"`
	Total    uint64           `json:"total"`
	TotalStr string           `json:"total_display"`
}

// PluginStep is one structured step in a plugin continuation flow.
type PluginStep struct {
	Message string   `json:"message,omitempty"`
	TxIDs   []string `json:"txids,omitempty"`
}

// Plugin is the canonical structured result for external plugin execution.
type Plugin struct {
	Plugin       string                `json:"plugin"`
	Success      bool                  `json:"success"`
	Message      string                `json:"message,omitempty"`
	TxIDs        []string              `json:"txids,omitempty"`
	Data         interface{}           `json:"data,omitempty"`
	Presentation *jsonrpc.Presentation `json:"presentation,omitempty"`
	Steps        []PluginStep          `json:"steps,omitempty"`
}

// AppDeploy is the canonical structured result for app deployment commands.
type AppDeploy struct {
	TxID       string `json:"tx_id"`
	Confirmed  bool   `json:"confirmed"`
	AppID      uint64 `json:"app_id,omitempty"`
	AppAddress string `json:"app_address,omitempty"`
}

// AppCall is the canonical structured result for app call commands.
type AppCall struct {
	AppID     uint64   `json:"app_id"`
	Method    string   `json:"method,omitempty"`
	Mode      string   `json:"mode"`
	Grouped   bool     `json:"grouped"`
	TxID      string   `json:"tx_id,omitempty"`
	TxIDs     []string `json:"tx_ids,omitempty"`
	Confirmed bool     `json:"confirmed"`
}

// StatusView is the appresult-owned projection input for MCP status payloads.
type StatusView struct {
	Network          string
	IsConnected      bool
	ConnectionTarget string
	WriteMode        bool
	ASACacheCount    int
	AliasCacheCount  int
	SetCacheCount    int
	SignerKeyCount   int
}

// AssetBalanceView is the appresult-owned projection input for one ASA holding.
type AssetBalanceView struct {
	AssetID  uint64
	Amount   uint64
	UnitName string
	Decimals uint64
	IsFrozen bool
}

// BalanceView is the appresult-owned projection input for balance payloads.
type BalanceView struct {
	Address     string
	Alias       string
	AlgoBalance uint64
	AuthAddr    string
	MinBalance  uint64
	Assets      []AssetBalanceView
}

// AccountView is the appresult-owned projection input for account listings.
type AccountView struct {
	Address    string
	Alias      string
	Source     string
	IsSignable bool
	KeyType    string
}

// AliasView is the appresult-owned projection input for alias listings.
type AliasView struct {
	Name       string
	Address    string
	IsSignable bool
	KeyType    string
}

// SetView is the appresult-owned projection input for set listings.
type SetView struct {
	Name      string
	Addresses []string
	Count     int
}

// ParticipationView is the appresult-owned projection input for participation payloads.
type ParticipationView struct {
	Address           string
	IsOnline          bool
	IncentiveEligible bool
	VoteKey           string
	SelectionKey      string
	StateProofKey     string
	VoteFirstValid    uint64
	VoteLastValid     uint64
	VoteKeyDilution   uint64
}

// ASAInfoView is the appresult-owned projection input for ASA metadata payloads.
type ASAInfoView struct {
	AssetID       uint64
	Name          string
	UnitName      string
	Decimals      uint64
	Total         uint64
	URL           string
	Creator       string
	Manager       string
	Reserve       string
	Freeze        string
	Clawback      string
	DefaultFrozen bool
}

// Marshal serializes a result payload and ignores encoding errors.
func Marshal(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}

// StatusToMCP projects an engine status result into the MCP status schema.
func StatusToMCP(result StatusView, sshTunnel bool) MCPStatus {
	return MCPStatus{
		Network:          result.Network,
		SignerConnected:  result.IsConnected,
		ConnectionTarget: result.ConnectionTarget,
		SSHTunnel:        sshTunnel,
		WriteMode:        result.WriteMode,
		ASACacheCount:    result.ASACacheCount,
		AliasCacheCount:  result.AliasCacheCount,
		SetCacheCount:    result.SetCacheCount,
		SignerKeyCount:   result.SignerKeyCount,
	}
}

// BalanceToMCP projects an engine balance result into the MCP balance schema.
func BalanceToMCP(result BalanceView) MCPBalance {
	projected := MCPBalance{
		Address:        result.Address,
		Alias:          result.Alias,
		AlgoBalance:    result.AlgoBalance,
		AlgoBalanceStr: asa.FormatDisplayAmount(result.AlgoBalance, asa.Metadata{Decimals: 6}),
		AuthAddr:       result.AuthAddr,
		MinBalance:     result.MinBalance,
	}
	for _, asset := range result.Assets {
		projected.Assets = append(projected.Assets, MCPAssetEntry{
			AssetID:   asset.AssetID,
			Amount:    asset.Amount,
			AmountStr: asa.FormatDisplayAmount(asset.Amount, asa.Metadata{Decimals: asset.Decimals}),
			UnitName:  asset.UnitName,
			Decimals:  asset.Decimals,
			IsFrozen:  asset.IsFrozen,
		})
	}
	return projected
}

// AccountsToMCP projects engine account info into the MCP account schema.
func AccountsToMCP(accounts []AccountView) []MCPAccount {
	projected := make([]MCPAccount, len(accounts))
	for i, account := range accounts {
		projected[i] = MCPAccount(account)
	}
	return projected
}

// AliasesToMCP projects engine alias listings into the MCP alias schema.
func AliasesToMCP(aliases []AliasView) []MCPAlias {
	projected := make([]MCPAlias, len(aliases))
	for i, alias := range aliases {
		projected[i] = MCPAlias(alias)
	}
	return projected
}

// SetsToMCP projects engine set listings into the MCP set schema.
func SetsToMCP(sets []SetView) []MCPSet {
	projected := make([]MCPSet, len(sets))
	for i, set := range sets {
		projected[i] = MCPSet(set)
	}
	return projected
}

// ParticipationToMCP projects engine participation status into the MCP schema.
func ParticipationToMCP(result ParticipationView, isRekeyed bool, authAddr string) MCPParticipation {
	projected := MCPParticipation{
		Address:           result.Address,
		IsOnline:          result.IsOnline,
		IncentiveEligible: result.IncentiveEligible,
		VoteKey:           result.VoteKey,
		SelectionKey:      result.SelectionKey,
		StateProofKey:     result.StateProofKey,
		VoteFirstValid:    result.VoteFirstValid,
		VoteLastValid:     result.VoteLastValid,
		VoteKeyDilution:   result.VoteKeyDilution,
	}
	if isRekeyed {
		projected.IsRekeyed = true
		projected.AuthAddr = authAddr
	}
	return projected
}

// ASAInfoToMCP projects engine ASA metadata into the MCP schema.
func ASAInfoToMCP(info ASAInfoView) MCPASAInfo {
	return MCPASAInfo(info)
}

// CachedASAsToMCP projects cached engine ASA entries into the MCP schema.
func CachedASAsToMCP(asas []ASAInfoView) []MCPASACacheEntry {
	projected := make([]MCPASACacheEntry, len(asas))
	for i, asa := range asas {
		projected[i] = MCPASACacheEntry{
			AssetID:  asa.AssetID,
			Name:     asa.Name,
			UnitName: asa.UnitName,
			Decimals: asa.Decimals,
		}
	}
	return projected
}

// HolderEntryToMCP projects one holder balance into the MCP holder schema.
func HolderEntryToMCP(address, alias string, rawBalance, decimals uint64) MCPHolderEntry {
	return MCPHolderEntry{
		Address:    address,
		Alias:      alias,
		Balance:    rawBalance,
		BalanceStr: asa.FormatDisplayAmount(rawBalance, asa.Metadata{Decimals: decimals}),
	}
}

// HoldersToMCP builds the top-level MCP holders payload.
func HoldersToMCP(asset string, decimals uint64, holders []MCPHolderEntry, totalRaw uint64) MCPHolders {
	return MCPHolders{
		Asset:    asset,
		Decimals: decimals,
		Holders:  holders,
		Total:    totalRaw,
		TotalStr: asa.FormatDisplayAmount(totalRaw, asa.Metadata{Decimals: decimals}),
	}
}

// FilterPluginData removes non-serializable shell-only data from plugin output.
func FilterPluginData(data interface{}) interface{} {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return data
	}

	filtered := make(map[string]interface{}, len(dataMap))
	for k, v := range dataMap {
		if k != "localSigners" {
			filtered[k] = v
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}
