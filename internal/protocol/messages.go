// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package protocol defines the WebSocket message types shared between
// aplane (server) and apadmin/TUI (client).
// This is the single source of truth for the wire protocol.
package protocol

// WebSocket message type constants
const (
	// Authentication message types (sent before any other messages)
	MsgTypeAuthRequired = "auth_required"
	MsgTypeAuth         = "auth"
	MsgTypeAuthResult   = "auth_result"

	// Signer state message types
	MsgTypeUnlock       = "unlock"
	MsgTypeUnlockResult = "unlock_result"
	MsgTypeSignRequest  = "sign_request"
	MsgTypeSignResponse = "sign_response"
	MsgTypeStatus       = "status"
	MsgTypeError        = "error"

	// Token provisioning message types (SSH-based token request approval)
	MsgTypeTokenProvisioningRequest  = "token_provisioning_request"
	MsgTypeTokenProvisioningResponse = "token_provisioning_response"

	// Key management message types
	MsgTypeListKeys       = "list_keys"
	MsgTypeKeysList       = "keys_list"
	MsgTypeGenerateKey    = "generate_key"
	MsgTypeGenerateResult = "generate_result"
	MsgTypeDeleteKey      = "delete_key"
	MsgTypeDeleteResult   = "delete_result"
	MsgTypeExportKey      = "export_key"
	MsgTypeExportResult   = "export_result"
	MsgTypeImportKey      = "import_key"
	MsgTypeImportResult   = "import_result"
	MsgTypeGetKeyDetails  = "get_key_details"
	MsgTypeKeyDetails     = "key_details"

	// Server-initiated notification message types
	MsgTypeKeysChanged  = "keys_changed"  // Sent when keys are reloaded
	MsgTypeSignerLocked = "signer_locked" // Sent when signer auto-locks (inactivity timeout)

	// Client displacement message types (for single-client IPC enforcement)
	MsgTypeClientExists    = "client_exists"    // Server → new client: another client is connected
	MsgTypeDisplaceConfirm = "displace_confirm" // New client → server: proceed with displacement
	MsgTypeDisplaced       = "displaced"        // Server → old client: you've been displaced
)

// BaseMessage is the base structure for all WebSocket messages
type BaseMessage struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"` // Unique request ID for correlation
}

// AuthRequiredMessage is sent by signer when a client connects
// Client must respond with AuthMessage before any other operations
type AuthRequiredMessage struct {
	BaseMessage
}

// AuthMessage is sent by apadmin to authenticate the IPC session
type AuthMessage struct {
	BaseMessage
	Passphrase string `json:"passphrase"`
}

// AuthResultMessage is sent back after an authentication attempt
type AuthResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// UnlockMessage is sent by apadmin to unlock the signer
type UnlockMessage struct {
	BaseMessage
	Passphrase string `json:"passphrase"`
}

// UnlockResultMessage is sent back after an unlock attempt
type UnlockResultMessage struct {
	BaseMessage
	Success  bool   `json:"success"`
	KeyCount int    `json:"key_count,omitempty"`
	Error    string `json:"error,omitempty"`
}

// PolicyViolation represents a dangerous transaction field detected by the policy linter
type PolicyViolation struct {
	Field    string `json:"field"`    // Field name (e.g., "RekeyTo", "CloseRemainderTo")
	Value    string `json:"value"`    // The problematic value
	Severity string `json:"severity"` // "warning" or "critical"
	Message  string `json:"message"`  // Human-readable explanation
}

// SignRequestMessage is sent to apadmin for approval
type SignRequestMessage struct {
	BaseMessage
	Address     string            `json:"address"`              // Auth address (which key to use)
	TxnSender   string            `json:"txn_sender"`           // Actual transaction sender
	Description string            `json:"description"`          // Human-readable transaction description
	Timestamp   int64             `json:"timestamp"`            // Unix timestamp of request
	FirstValid  uint64            `json:"first_valid"`          // First valid round (0 if unknown)
	LastValid   uint64            `json:"last_valid"`           // Last valid round (0 if unknown)
	Violations  []PolicyViolation `json:"violations,omitempty"` // Policy violations detected
}

// SignResponseMessage is sent by apadmin with approval/rejection
type SignResponseMessage struct {
	BaseMessage
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"` // Optional rejection reason
}

// TokenProvisioningRequestMessage is sent to apadmin when a client requests a token via SSH
type TokenProvisioningRequestMessage struct {
	BaseMessage
	IdentityID     string `json:"identity_id"`     // Identity requesting token (e.g., "default")
	SSHFingerprint string `json:"ssh_fingerprint"` // SSH key fingerprint of requester
	RemoteAddr     string `json:"remote_addr"`     // Remote address of requester
	Timestamp      int64  `json:"timestamp"`       // Unix timestamp of request
}

// TokenProvisioningResponseMessage is sent by apadmin with approval/rejection
type TokenProvisioningResponseMessage struct {
	BaseMessage
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"` // Optional rejection reason
}

// StatusMessage is sent to communicate signer status
type StatusMessage struct {
	BaseMessage
	State    string `json:"state"`
	KeyCount int    `json:"key_count"`
}

// ErrorMessage is sent for error conditions
type ErrorMessage struct {
	BaseMessage
	Error string `json:"error"`
}

// ListKeysMessage requests the list of keys from signer
type ListKeysMessage struct {
	BaseMessage
}

// KeyInfo represents information about a single key in the wire protocol
type KeyInfo struct {
	Address string `json:"address"`
	KeyType string `json:"key_type"` // Full versioned type: "ed25519", "falcon1024-v1", etc.
	Name    string `json:"name,omitempty"`
}

// KeysListMessage contains the list of keys from signer
type KeysListMessage struct {
	BaseMessage
	Keys []KeyInfo `json:"keys"`
}

// GenerateKeyMessage requests generation of a new key
type GenerateKeyMessage struct {
	BaseMessage
	KeyType    string            `json:"key_type"` // Versioned key type: "ed25519", "falcon1024-v1", "timelock-v1", etc.
	Name       string            `json:"name,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"` // Template parameters (for generic lsigs like timelock)
}

// GenerateResultMessage contains the result of key generation
type GenerateResultMessage struct {
	BaseMessage
	Success    bool              `json:"success"`
	Address    string            `json:"address,omitempty"`
	KeyType    string            `json:"key_type,omitempty"` // Full versioned type: "ed25519", "falcon1024-v1", etc.
	Mnemonic   string            `json:"mnemonic,omitempty"` // Recovery phrase (shown once, then cleared)
	WordCount  int               `json:"word_count,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"` // Creation parameters needed for address re-derivation
	Error      string            `json:"error,omitempty"`
}

// DeleteKeyMessage requests deletion of a key
type DeleteKeyMessage struct {
	BaseMessage
	Address string `json:"address"`
}

// DeleteResultMessage contains the result of key deletion
type DeleteResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ExportKeyMessage requests export of a key's mnemonic
type ExportKeyMessage struct {
	BaseMessage
	Address    string `json:"address"`
	Passphrase string `json:"passphrase"` // Required to verify user identity before export
}

// ExportResultMessage contains the result of key export
type ExportResultMessage struct {
	BaseMessage
	Success    bool              `json:"success"`
	Address    string            `json:"address,omitempty"`
	KeyType    string            `json:"key_type,omitempty"` // Full versioned type: "ed25519", "falcon1024-v1", etc.
	Mnemonic   string            `json:"mnemonic,omitempty"` // The recovery phrase
	WordCount  int               `json:"word_count,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"` // Creation parameters needed for address re-derivation
	Error      string            `json:"error,omitempty"`
}

// ImportKeyMessage requests import of a key from mnemonic
type ImportKeyMessage struct {
	BaseMessage
	KeyType    string            `json:"key_type"` // Versioned key type: "ed25519", "falcon1024-v1", etc.
	Mnemonic   string            `json:"mnemonic"` // The recovery phrase
	Parameters map[string]string `json:"parameters,omitempty"`
}

// ImportResultMessage contains the result of key import
type ImportResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Address string `json:"address,omitempty"`
	KeyType string `json:"key_type,omitempty"`
	Error   string `json:"error,omitempty"`
}

// GetKeyDetailsMessage requests detailed information about a key
type GetKeyDetailsMessage struct {
	BaseMessage
	Address string `json:"address"`
}

// KeyDetailsMessage contains detailed information about a key
type KeyDetailsMessage struct {
	BaseMessage
	Success     bool              `json:"success"`
	Address     string            `json:"address,omitempty"`
	KeyType     string            `json:"key_type,omitempty"`
	Parameters  map[string]string `json:"parameters,omitempty"`   // For generic LogicSigs: recipient, unlock_round, etc.
	DisplayTEAL string            `json:"display_teal,omitempty"` // TEAL source for generic LogicSigs (actual compiled source)
	Error       string            `json:"error,omitempty"`
}

// KeysChangedMessage is sent by the server to notify clients that the key list has changed
type KeysChangedMessage struct {
	BaseMessage
	KeyCount int `json:"key_count"` // Number of keys after reload
}

// SignerLockedMessage is sent by the server to notify clients that the signer has locked
// (e.g., due to inactivity timeout). Client should transition to the unlock screen.
type SignerLockedMessage struct {
	BaseMessage
	Reason string `json:"reason"` // Why the signer locked (e.g., "inactivity timeout")
}

// ClientExistsMessage is sent by the server to a new client when another apadmin is already connected.
// The new client should show a confirmation prompt before proceeding.
type ClientExistsMessage struct {
	BaseMessage
}

// DisplaceConfirmMessage is sent by the new client to confirm displacement of the existing client.
type DisplaceConfirmMessage struct {
	BaseMessage
}

// DisplacedMessage is sent by the server to the old client when it is being displaced by a new client.
type DisplacedMessage struct {
	BaseMessage
	Reason string `json:"reason"`
}
