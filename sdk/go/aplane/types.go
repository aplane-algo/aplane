// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package aplane

// RuntimeArg describes a runtime argument for generic LogicSig keys.
type RuntimeArg struct {
	Name        string `json:"name"`                  // Internal name (e.g., "preimage")
	Label       string `json:"label"`                 // Human-readable label for UI
	Description string `json:"description,omitempty"` // Help text
	Type        string `json:"type"`                  // "bytes", "string", "uint64"
	Required    bool   `json:"required"`              // If true, must be provided at signing time
	ByteLength  int    `json:"byte_length,omitempty"` // Expected byte length (0 = variable)
}

// KeyInfo represents a signing key from the signer.
type KeyInfo struct {
	Address       string       `json:"address"`
	PublicKeyHex  string       `json:"public_key_hex"`
	KeyType       string       `json:"key_type"`
	LsigSize      int          `json:"lsig_size,omitempty"`
	IsGenericLsig bool         `json:"is_generic_lsig,omitempty"`
	RuntimeArgs   []RuntimeArg `json:"runtime_args,omitempty"`
}

// SignRequest is the request payload for signing a transaction.
type SignRequest struct {
	AuthAddress  string            `json:"auth_address,omitempty"`
	TxnSender    string            `json:"txn_sender,omitempty"`
	TxnBytesHex  string            `json:"txn_bytes_hex,omitempty"`
	LsigArgs     map[string]string `json:"lsig_args,omitempty"`
	SignedTxnHex string            `json:"signed_txn_hex,omitempty"`
}

// groupSignRequest is the internal request payload for the /sign endpoint.
type groupSignRequest struct {
	Requests []SignRequest `json:"requests"`
}

// MutationReport describes modifications made by the server during signing.
type MutationReport struct {
	DummiesAdded     int    `json:"dummies_added,omitempty"`
	GroupIDChanged   bool   `json:"group_id_changed,omitempty"`
	FeesModified     []int  `json:"fees_modified,omitempty"`
	TotalFeesDelta   int    `json:"total_fees_delta,omitempty"`
	OriginalCount    int    `json:"original_count,omitempty"`
	FinalCount       int    `json:"final_count,omitempty"`
	PassthroughCount int    `json:"passthrough_count,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// GroupSignResponse is the response from the /sign endpoint.
type GroupSignResponse struct {
	Signed    []string        `json:"signed,omitempty"`
	Mutations *MutationReport `json:"mutations,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// keysResponse is the internal response from the /keys endpoint.
type keysResponse struct {
	Count int       `json:"count"`
	Keys  []KeyInfo `json:"keys"`
}

// LsigArgs is a map of argument name to value for generic LogicSigs.
type LsigArgs map[string][]byte

// LsigArgsMap maps addresses to their LogicSig arguments.
type LsigArgsMap map[string]LsigArgs

// SSHConfig contains SSH tunnel configuration.
type SSHConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	IdentityFile   string `yaml:"identity_file"`
	KnownHostsPath string `yaml:"known_hosts_path"`
}

// Config contains client configuration loaded from config.yaml.
type Config struct {
	SignerPort int        `yaml:"signer_port"`
	SSH        *SSHConfig `yaml:"ssh,omitempty"`
}

// ConnectOptions contains options for connecting to the signer.
type ConnectOptions struct {
	Host    string
	Port    int
	Timeout int // seconds
}

// SSHConnectOptions contains options for SSH tunnel connections.
type SSHConnectOptions struct {
	SSHPort    int
	SignerPort int
	Timeout    int // seconds
}

// FromEnvOptions contains options for FromEnv().
type FromEnvOptions struct {
	DataDir string
	Timeout int // seconds
}
