// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// StatusResult holds data for the status command
type StatusResult struct {
	Network          string
	IsConnected      bool
	ConnectionTarget string
	SigningMode      string // "remote", "disconnected"
	WriteMode        bool
	ASACacheCount    int
	AliasCacheCount  int
	SetCacheCount    int
	SignerCacheCount int
}

// BalanceResult holds account balance information
type BalanceResult struct {
	Address     string
	Alias       string // empty if no alias
	AlgoBalance uint64 // microAlgos
	Assets      []AssetBalance
	AuthAddr    string // if rekeyed
	MinBalance  uint64
}

// AssetBalance represents a single ASA holding
type AssetBalance struct {
	AssetID   uint64
	Amount    uint64
	UnitName  string
	Decimals  uint64
	IsFrozen  bool
	IsOptedIn bool
}

// AccountInfo represents a known account
type AccountInfo struct {
	Address    string
	Alias      string
	Source     string // "alias", "signer", "set"
	IsSignable bool
	KeyType    string // "ed25519", "aplane.falcon1024.v1", "aplane.htlc.v1", etc.
}

// KeyInfo represents a remote signing key from Signer
type KeyInfo struct {
	Address                  string            `json:"address"`
	KeyType                  string            `json:"key_type"` // "ed25519", "aplane.falcon1024.v1", "aplane.htlc.v1", etc.
	PublicKeyHex             string            `json:"public_key_hex"`
	Parameters               map[string]string `json:"parameters,omitempty"`
	TemplateProvenanceStatus string            `json:"template_provenance_status,omitempty"`
	TemplateProvenanceNote   string            `json:"template_provenance_note,omitempty"`
	// PolicyLabel describes a bounded account's stored contract.
	PolicyLabel string `json:"policy_label,omitempty"`
	// CosignerKeyID is the signer's identity for a bounded account's cosigner.
	CosignerKeyID string `json:"cosigner_key_id,omitempty"`
	// IsGenericLsig is set for a generic LogicSig aplane key, whose program
	// decides what can be signed.
	IsGenericLsig bool `json:"is_generic_lsig,omitempty"`
	// ValidRekeyTarget is the valid_rekey_target this aplane key recorded when
	// it was created: whether an account may be rekeyed to it.
	ValidRekeyTarget bool `json:"valid_rekey_target"`
}

// ASAInfo holds asset metadata
type ASAInfo struct {
	AssetID       uint64
	UnitName      string
	Name          string
	Decimals      uint64
	Total         uint64
	Creator       string
	Manager       string
	Reserve       string
	Freeze        string
	Clawback      string
	DefaultFrozen bool
	URL           string
}

// ConnectionResult holds a successful connection's outcome
type ConnectionResult struct {
	AlreadyConnected bool
	Target           string
	KeyCount         int
	Locked           bool // Signer is locked (keys not accessible until unlocked)
}

// ParticipationResult holds consensus participation status for an account
type ParticipationResult struct {
	Address           string
	IsOnline          bool
	VoteKey           string
	SelectionKey      string
	StateProofKey     string
	VoteFirstValid    uint64
	VoteLastValid     uint64
	VoteKeyDilution   uint64
	IncentiveEligible bool
}

// GenerateKeyResult holds the result of key generation
type GenerateKeyResult struct {
	Address string
	KeyType string
	// Parameters are the canonical values the signer resolved and stored.
	Parameters map[string]string
	// CosignerKeyID is the signer's own identity for the account's cosigner, read
	// back from /keys. It is empty when the account has none, or when the
	// inventory could not be read.
	CosignerKeyID string
	// InventoryRead reports whether it came from the signer.
	InventoryRead bool
	// Warnings are the signer's advice about the account it created.
	Warnings []string
}
