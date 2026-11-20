// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package jsonrpc defines the methods and types for plugin communication
package jsonrpc

import "github.com/algorand/go-algorand-sdk/v2/types"

// Standard methods that all plugins must implement
const (
	MethodInitialize = "initialize"
	MethodExecute    = "execute"
	MethodShutdown   = "shutdown"
)

// PluginProtocol identifies the APlane plugin protocol declared by a plugin
// during initialization. The host does not send this value to the plugin: the
// declaration must come from plugin-owned code rather than echoing host input.
// It is distinct from the JSON-RPC envelope version and the plugin package's
// semantic version in its manifest.
const PluginProtocol = "aplane-plugin/2"

// Optional methods a plugin may implement.
const (
	// MethodSignTransactions is a host->plugin call used in the pre-sign planning
	// flow: after APlane canonicalizes the group, it asks the plugin to sign the
	// slots it owns (declared via ExecuteResult.PluginSigners) over the canonical
	// bytes, so the plugin's signing material is never exported to APlane.
	MethodSignTransactions = "signTransactions"
)

// InitializeParams sent when initializing a plugin
type InitializeParams struct {
	Network    string `json:"network"`    // Network context token
	AlgodURL   string `json:"algodUrl"`   // Algorand node API URL
	AlgodToken string `json:"algodToken"` // Algod API token (empty for public nodes)
}

// InitializeResult returned from plugin initialization
type InitializeResult struct {
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
	Protocol string `json:"protocol"` // Plugin-owned APlane protocol declaration
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

	// PluginSigners declares slots the plugin owns but will sign itself, by
	// reference, in the pre-sign planning flow (GroupModePresignPlan). APlane never
	// receives the signing material; it calls MethodSignTransactions to have the
	// plugin sign these slots over the canonical group.
	PluginSigners []PluginSigner `json:"pluginSigners,omitempty"`

	// GroupMode selects how APlane handles Transactions. Empty (the default)
	// means APlane-managed unsigned transactions. GroupModePregroupedSigned means
	// the plugin supplied a complete, already-signed, already-grouped atomic group
	// that APlane validates and submits verbatim (no apsigner, no /plan).
	GroupMode string `json:"groupMode,omitempty"`
}

// Group modes for ExecuteResult.GroupMode. These are the general extension point that
// lets a plugin take part in building/signing atomic groups involving cryptography
// APlane does not hold (a LogicSig, an HSM/MPC key, a counterparty's signature) — the
// substrate for external-custody, smart-signature, counterparty/relayer, and privacy
// plugins. See docs/ARCH_PLUGINS.md "Plugin Transaction Flows".
const (
	// GroupModePregroupedSigned: Transactions are all Type:"signed", form one
	// complete signed atomic group, and are submitted verbatim. Incompatible with
	// any APlane-managed signing.
	GroupModePregroupedSigned = "pregrouped-signed"

	// GroupModePresignPlan: Transactions are unsigned; APlane canonicalizes the
	// group (budget txns, fees, group ID) preserving the plugin slots' fields, then
	// calls MethodSignTransactions for PluginSigners-owned slots and signs any
	// APlane-managed slots itself. Used for a group that mixes plugin-owned
	// non-exportable signers with APlane-managed funders (e.g. a Mithras deposit).
	GroupModePresignPlan = "presign-plan"
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
// Type "raw": Encoded is a base64 unsigned transaction msgpack; APlane signs
// and submits it. Type "signed": Encoded is a base64 signed transaction msgpack;
// valid only when ExecuteResult.GroupMode is
// GroupModePregroupedSigned, where APlane submits it verbatim.
type TransactionIntent struct {
	Type    string `json:"type"`    // "raw" (unsigned) or "signed" (pregrouped-signed)
	Encoded string `json:"encoded"` // Base64-encoded transaction msgpack (unsigned for raw, signed for signed)
}

// Transaction intent types.
const (
	TransactionIntentRaw    = "raw"
	TransactionIntentSigned = "signed"
)

// PluginSigner declares, by reference, a slot the plugin will sign itself during
// pre-sign planning. No signing material is exported; SignerRef is opaque to APlane
// and is echoed back in the MethodSignTransactions request so the plugin can locate
// its key (e.g. a Mithras stealth account or UTXO id).
type PluginSigner struct {
	Address   string `json:"address"`
	Kind      string `json:"kind"`      // e.g. "plugin-callback"
	SignerRef string `json:"signerRef"` // opaque plugin-owned identifier
	// LsigResources declares the selected authorization path the plugin will
	// attach during signTransactions. APlane cannot derive these values while the
	// slot is unsigned and the program remains plugin-private. Omit it only when
	// the slot carries no LogicSig.
	LsigResources *PluginLogicSigResources `json:"lsigResources,omitempty"`
	// PQScheme declares the native-PQ authorization the plugin will attach.
	// It is mutually exclusive with LsigResources; "f1" is Falcon-1024.
	PQScheme string `json:"pqScheme,omitempty"`
}

// PluginLogicSigResources keeps the three v42 consensus resources separate.
// MaxOpcodeCost is a reviewed worst-case ceiling for the selected path, not a
// value sampled from one execution.
type PluginLogicSigResources struct {
	ProgramBytes  uint64 `json:"programBytes"`
	ArgumentBytes uint64 `json:"argumentBytes"`
	MaxOpcodeCost uint64 `json:"maxOpcodeCost"`
}

// PluginSignerKind values.
const (
	PluginSignerKindCallback = "plugin-callback"
)

// SignTransactionsParams is the host->plugin request asking the plugin to sign the
// canonical (post-/plan) bytes for the slots it owns.
type SignTransactionsParams struct {
	Requests []SignTransactionRequest `json:"requests"`
}

// SignTransactionRequest identifies one slot the plugin must sign.
type SignTransactionRequest struct {
	Index     int    `json:"index"`     // position in the canonical group
	Address   string `json:"address"`   // sender of the slot
	SignerRef string `json:"signerRef"` // echoed from the PluginSigner declaration
	Encoded   string `json:"encoded"`   // base64 canonical unsigned transaction msgpack
}

// SignTransactionsResult returns the plugin's signed blobs, by index.
type SignTransactionsResult struct {
	Signed []SignedTxnEntry `json:"signed"`
}

// SignedTxnEntry is one plugin-signed transaction.
type SignedTxnEntry struct {
	Index   int    `json:"index"`   // matches the request index
	Encoded string `json:"encoded"` // base64 signed transaction msgpack
}

// ShutdownParams (empty for now)
type ShutdownParams struct{}

// ShutdownResult confirms shutdown
type ShutdownResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}
