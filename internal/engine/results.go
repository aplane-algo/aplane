// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

// StatusResult holds data for the status command
type StatusResult struct {
	Network          string
	IsConnected      bool
	ConnectionTarget string
	SigningMode      string // "local", "remote", "disconnected"
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
	KeyType    string // "ed25519", "falcon1024-v1", "timelock-v1", etc.
}

// KeyInfo represents a remote signing key from Signer
type KeyInfo struct {
	Address      string
	KeyType      string // "ed25519", "falcon1024-v1", "timelock-v1", etc.
	PublicKeyHex string
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

// TransactionResult holds the outcome of a single transaction
type TransactionResult struct {
	TxID           string
	GroupID        string // for atomic groups
	ConfirmedRound uint64
	Fee            uint64
	Sender         string
	Receiver       string // may be empty for non-payment
	Amount         uint64
	AssetID        uint64 // 0 for ALGO
	Note           string
	WroteToFile    string // file path if write mode enabled
}

// SendResult holds results for send operations (may be multiple txns)
type SendResult struct {
	Transactions []TransactionResult
	TotalFee     uint64
	IsAtomic     bool
}

// SignResult holds the result of signing a transaction
type SignResult struct {
	TxID        string
	SignedBlob  []byte
	WroteToFile string
}

// RekeyResult holds rekey operation data
type RekeyResult struct {
	Address     string
	OldAuthAddr string
	NewAuthAddr string
	TxID        string
}

// ConnectionResult holds connection attempt outcome
type ConnectionResult struct {
	Connected    bool
	Target       string
	Port         int
	KeyCount     int
	ErrorMessage string
}

// ScriptResult holds script execution outcome
type ScriptResult struct {
	LinesExecuted int
	CommandsRun   int
	Errors        []ScriptError
	Completed     bool
}

// ScriptError represents a single error during script execution
type ScriptError struct {
	LineNumber int
	Command    string
	Error      string
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

// AliasResult holds the result of an alias operation
type AliasResult struct {
	Name    string
	Address string
	Created bool // true if new, false if updated
}

// SetResult holds the result of a set operation
type SetResult struct {
	Name      string
	Addresses []string
	Created   bool // true if new, false if updated
}
