// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

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
	Network    string `json:"network"`    // testnet, mainnet, betanet
	APIServer  string `json:"apiServer"`  // Algorand node API URL
	APIToken   string `json:"apiToken"`   // API token if needed
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

	// Asset resolution: ASA name -> asset ID mapping
	// Example: {"USDC": 10458941, "ALGO": 0}
	AssetMap map[string]uint64 `json:"assetMap,omitempty"`

	// Address resolution: alias -> address mapping
	// Example: {"alice": "ALICE_ADDRESS...", "bob": "BOB_ADDRESS..."}
	AddressMap map[string]string `json:"addressMap,omitempty"`

	// Network information
	Network     string `json:"network"`
	Round       uint64 `json:"round"`
	GenesisID   string `json:"genesisId"`
	GenesisHash string `json:"genesisHash"`

	// Transaction context
	SuggestedParams *types.SuggestedParams `json:"suggestedParams,omitempty"`

	// Continuation context (for multi-step workflows)
	Continuation map[string]interface{} `json:"continuation,omitempty"`
}

// ExecuteResult returned from command execution
type ExecuteResult struct {
	Success          bool                `json:"success"`
	Message          string              `json:"message,omitempty"`
	Transactions     []TransactionIntent `json:"transactions,omitempty"`
	Data             interface{}         `json:"data,omitempty"`
	RequiresApproval bool                `json:"requiresApproval,omitempty"`
	Continuation     *Continuation       `json:"continuation,omitempty"` // For multi-step workflows
}

// Continuation describes the next step in a multi-step workflow
type Continuation struct {
	Command string                 `json:"command"`           // Command to execute next
	Args    []string               `json:"args"`              // Arguments for next step
	Context map[string]interface{} `json:"context"`           // Additional context to pass
	Message string                 `json:"message,omitempty"` // Optional message to display before next step
}

// TransactionIntent represents a transaction the plugin wants to create
type TransactionIntent struct {
	Type        string                 `json:"type"` // payment, asset-transfer, app-call, raw, etc.
	From        string                 `json:"from,omitempty"`
	To          string                 `json:"to,omitempty"`
	Amount      uint64                 `json:"amount,omitempty"`
	AssetID     uint64                 `json:"assetId,omitempty"`
	AppID       uint64                 `json:"appId,omitempty"`
	AppArgs     [][]byte               `json:"appArgs,omitempty"`
	Note        []byte                 `json:"note,omitempty"`
	Encoded     string                 `json:"encoded,omitempty"` // Base64-encoded raw transaction (for type:"raw")
	Description string                 `json:"description"`       // Human-readable description
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
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

// LogParams for logging callback
type LogParams struct {
	Level   string `json:"level"` // debug, info, warn, error
	Message string `json:"message"`
}

// LogResult confirms log received
type LogResult struct {
	Success bool `json:"success"`
}
