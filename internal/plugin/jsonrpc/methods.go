// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package jsonrpc defines the methods and types for plugin communication
package jsonrpc

import (
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Standard methods that all plugins must implement
const (
	MethodInitialize = "initialize"
	MethodExecute    = "execute"
	MethodGetInfo    = "getInfo"
	MethodShutdown   = "shutdown"
)

// InitializeParams sent when initializing a plugin
type InitializeParams struct {
	Network    string `json:"network"`    // Network context token
	AlgodURL   string `json:"algodUrl"`   // Algorand node API URL
	AlgodToken string `json:"algodToken"` // Algod API token (empty for public nodes)
	IndexerURL string `json:"indexerUrl"` // Indexer URL if available
	Version    string `json:"version"`    // apshell version
}

// InitializeResult returned from plugin initialization
type InitializeResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Version string `json:"version"` // Plugin version
}

// ExecuteParams sent when executing a command
type ExecuteParams struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Context Context  `json:"context"`
}

// Context provides execution context to the plugin
type Context struct {
	// Available accounts (addresses that can sign transactions)
	Accounts []string `json:"accounts"`

	// Assets is the structured asset context for known ASAs.
	Assets []ContextAsset `json:"assets,omitempty"`

	// Address resolution: alias -> address mapping
	// Example: {"alice": "ALICE_ADDRESS...", "bob": "BOB_ADDRESS..."}
	AddressMap map[string]string `json:"addressMap,omitempty"`

	// Network information
	Network     string `json:"network"`
	Round       uint64 `json:"round,omitempty"`
	GenesisID   string `json:"genesisId,omitempty"`
	GenesisHash string `json:"genesisHash,omitempty"`

	// Transaction context
	SuggestedParams *types.SuggestedParams `json:"suggestedParams,omitempty"`

	// Continuation context (for multi-step workflows)
	Continuation map[string]interface{} `json:"continuation,omitempty"`
}

// ContextAsset is structured ASA metadata exposed to plugins.
type ContextAsset struct {
	AssetID  uint64 `json:"assetId"`
	Name     string `json:"name,omitempty"`
	UnitName string `json:"unitName,omitempty"`
	Decimals uint64 `json:"decimals"`
}

// ExecuteResult returned from command execution
type ExecuteResult struct {
	Success          bool                `json:"success"`
	Message          string              `json:"message,omitempty"`
	Transactions     []TransactionIntent `json:"transactions,omitempty"`
	Data             interface{}         `json:"data,omitempty"`
	Presentation     *Presentation       `json:"presentation,omitempty"`
	RequiresApproval bool                `json:"requiresApproval,omitempty"`
	Continuation     *Continuation       `json:"continuation,omitempty"` // For multi-step workflows
	LocalSigners     []LocalSigner       `json:"localSigners,omitempty"`

	// GroupMode selects how APlane handles Transactions. Empty (the default) is
	// the legacy unsigned/localSigners path. GroupModePregroupedSigned means the
	// plugin supplied a complete, already-signed, already-grouped atomic group
	// that APlane validates and submits verbatim (no apsigner, no /plan).
	GroupMode string `json:"groupMode,omitempty"`
}

// Group modes for ExecuteResult.GroupMode.
const (
	// GroupModePregroupedSigned: Transactions are all Type:"signed", form one
	// complete signed atomic group, and are submitted verbatim. Incompatible with
	// LocalSigners or any APlane-managed signing.
	GroupModePregroupedSigned = "pregrouped-signed"
)

// Presentation is optional plugin-supplied display metadata for human-oriented shell output.
// Data remains the canonical machine-readable payload; presentation is a rendering hint.
type Presentation struct {
	Title    string                `json:"title,omitempty"`
	Summary  string                `json:"summary,omitempty"`
	Sections []PresentationSection `json:"sections,omitempty"`
}

// PresentationSection is one renderable block in plugin presentation output.
type PresentationSection struct {
	Kind    string                 `json:"kind"` // text, key_value, table
	Title   string                 `json:"title,omitempty"`
	Text    string                 `json:"text,omitempty"`
	Items   []PresentationItem     `json:"items,omitempty"`
	Columns []string               `json:"columns,omitempty"`
	Rows    []PresentationTableRow `json:"rows,omitempty"`
}

// PresentationItem is one human-readable key/value item.
type PresentationItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// PresentationTableRow is one table row.
type PresentationTableRow struct {
	Cells []string `json:"cells"`
}

// Continuation describes the next step in a multi-step workflow
type Continuation struct {
	Command string                 `json:"command"`           // Command to execute next
	Args    []string               `json:"args"`              // Arguments for next step
	Context map[string]interface{} `json:"context"`           // Additional context to pass
	Message string                 `json:"message,omitempty"` // Optional message to display before next step
}

// TransactionIntent represents a transaction the plugin wants to create.
//
// Type "raw": Encoded is a base64 unsigned transaction msgpack; APlane plans,
// signs, and submits it (legacy path). Type "signed": Encoded is a base64 signed
// transaction msgpack; valid only when ExecuteResult.GroupMode is
// GroupModePregroupedSigned, where APlane submits it verbatim.
type TransactionIntent struct {
	Type    string `json:"type"`    // "raw" (unsigned) or "signed" (pregrouped-signed only)
	Encoded string `json:"encoded"` // Base64-encoded transaction msgpack (unsigned for raw, signed for signed)
}

// Transaction intent types.
const (
	TransactionIntentRaw    = "raw"
	TransactionIntentSigned = "signed"
)

// LocalSigner is a plugin-controlled ephemeral signer supplied in an execute result.
type LocalSigner struct {
	Address   string `json:"address"`
	SecretKey string `json:"secretKey"` // Base64-encoded 64-byte Ed25519 secret key.
}

// GetInfoParams (empty for now, may extend later)
type GetInfoParams struct{}

// GetInfoResult provides plugin information
type GetInfoResult struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Author      string   `json:"author,omitempty"`
	Commands    []string `json:"commands"`
	Networks    []string `json:"networks"`
	Status      string   `json:"status"` // ready, busy, error
}

// ShutdownParams (empty for now)
type ShutdownParams struct{}

// ShutdownResult confirms shutdown
type ShutdownResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// Callbacks that plugins can make to apshell
const (
	CallbackGetAccount      = "getAccount"
	CallbackListAccounts    = "listAccounts"
	CallbackGetBalance      = "getBalance"
	CallbackGetAssetInfo    = "getAssetInfo"
	CallbackGetAppInfo      = "getAppInfo"
	CallbackSignTransaction = "signTransaction"
	CallbackLog             = "log"
)

// GetAccountParams for account info callback
type GetAccountParams struct {
	Address string `json:"address"`
}

// GetAccountResult returns account information
type GetAccountResult struct {
	Address string          `json:"address"`
	Balance uint64          `json:"balance"`
	Assets  []AssetHolding  `json:"assets,omitempty"`
	Apps    []AppLocalState `json:"apps,omitempty"`
}

// ListAccountsParams for account listing callback.
type ListAccountsParams struct{}

// ListAccountsResult returns all accounts available to the plugin host.
type ListAccountsResult struct {
	Accounts []string `json:"accounts"`
}

// AssetHolding represents an asset holding
type AssetHolding struct {
	AssetID  uint64 `json:"assetId"`
	Amount   uint64 `json:"amount"`
	IsFrozen bool   `json:"isFrozen"`
}

// AppLocalState represents local app state
type AppLocalState struct {
	AppID     uint64                 `json:"appId"`
	KeyValues map[string]interface{} `json:"keyValues"`
}

// GetBalanceParams for balance query
type GetBalanceParams struct {
	Address string `json:"address"`
	AssetID uint64 `json:"assetId,omitempty"` // 0 for ALGO
}

// GetBalanceResult returns balance
type GetBalanceResult struct {
	Balance uint64 `json:"balance"`
}

// GetAssetInfoParams for ASA metadata lookup.
type GetAssetInfoParams struct {
	AssetID uint64 `json:"assetId"`
}

// GetAssetInfoResult returns ASA metadata.
type GetAssetInfoResult struct {
	AssetID  uint64 `json:"assetId"`
	Name     string `json:"name,omitempty"`
	UnitName string `json:"unitName,omitempty"`
	Decimals uint64 `json:"decimals"`
}

// GetAppInfoParams for application metadata lookup.
type GetAppInfoParams struct {
	AppID uint64 `json:"appId"`
}

// GetAppInfoResult returns application metadata.
type GetAppInfoResult struct {
	AppID       uint64                 `json:"appId"`
	Creator     string                 `json:"creator,omitempty"`
	GlobalState map[string]interface{} `json:"globalState,omitempty"`
}

// SignTransactionParams asks the host to sign one base64-encoded unsigned transaction.
type SignTransactionParams struct {
	Encoded     string `json:"encoded"`
	Description string `json:"description,omitempty"`
}

// SignTransactionResult returns one base64-encoded signed transaction.
type SignTransactionResult struct {
	Signed string `json:"signed"`
}

// LogParams for logging callback
type LogParams struct {
	Level   string `json:"level"` // debug, info, warn, error
	Message string `json:"message"`
}

// LogResult confirms log received
type LogResult struct {
	Success bool `json:"success"`
}
