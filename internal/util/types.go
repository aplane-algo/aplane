// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ASAInfo contains information about an Algorand Standard Asset
type ASAInfo struct {
	Decimals uint64 `json:"decimals"`
	Name     string `json:"name"`
	UnitName string `json:"unit_name"`
}

// ASACache stores cached ASA information per network
type ASACache struct {
	Assets map[uint64]ASAInfo `json:"assets"`
}

// AliasCache stores address aliases
type AliasCache struct {
	Aliases map[string]string `json:"aliases"`
}

// LSigConfig represents a LogicSig configuration for any signature scheme
type LSigConfig struct {
	LSigFile    string            `json:"lsig_file"`
	Category    string            `json:"category"` // "dsa_lsig" or "generic_lsig"
	Address     string            `json:"address"`
	Description string            `json:"description"`
	KeyType     string            `json:"key_type"`             // e.g., "falcon1024-v1", "timelock-v1" (required)
	Template    string            `json:"template,omitempty"`   // Template name for generic lsigs (e.g., "timelock")
	Parameters  map[string]string `json:"parameters,omitempty"` // Template parameters (e.g., recipient, unlock_round)
	Bytecode    []byte            `json:"-"`                    // In-memory bytecode (session cache, not serialized)
}

// Note: Generic LogicSig key types (timelock, etc.) are now managed by the
// genericlsig registry. Use genericlsig.IsGenericLSigType() for type checking.

// SignerCache stores addresses that Signer has private keys for (can sign remotely)
// Maps: address -> key type ("falcon1024-v1" or "ed25519")
type SignerCache struct {
	Keys           map[string]string           `json:"keys"`          // address -> key type
	GenericLsigs   map[string]bool             `json:"generic_lsigs"` // address -> true if generic lsig (no signature needed)
	LsigSizes      map[string]int              `json:"lsig_sizes"`    // address -> total LSig size (bytecode + crypto sig) for budget calculation
	RuntimeArgs    map[string][]RuntimeArgInfo `json:"runtime_args"`  // address -> runtime args schema for generic lsigs
	Checksum       string                      `json:"checksum"`      // checksum of keys for cache validation
	Locked         bool                        `json:"-"`             // True if signer reported 403 (locked) on last /keys check
	colorFormatter ColorFormatter              // Function to get display color by key type (not serialized)
}

// AuthAddressCache stores cached auth addresses to avoid repeated blockchain queries
// Maps: account address -> auth address (empty string if not rekeyed)
type AuthAddressCache struct {
	AuthAddresses map[string]string `json:"auth_addresses"` // address -> auth address (or "" if not rekeyed)
}

// SignerClient is an HTTP client for the Signer signing service
type SignerClient struct {
	BaseURL string
	Token   string // Bearer token for authentication
	Client  *http.Client
}

// SignRequest is the request payload for Signer signing.
// Three modes are supported (mutually exclusive):
//   - Sign mode: auth_address + txn_bytes_hex (server signs with its key)
//   - Passthrough mode: signed_txn_hex (already signed, included as-is)
//   - Foreign mode: txn_bytes_hex without auth_address (belongs to another signer)
//
// Passthrough mode requires pre-grouped transactions (group ID already set).
// Foreign mode includes the transaction in group building (dummies, fees, group ID)
// but does not sign it. The optional lsig_size hint reserves LSig budget for the
// foreign party's key type.
type SignRequest struct {
	// Sign mode fields (server signs this transaction)
	AuthAddress string            `json:"auth_address,omitempty"`  // Auth address (which key to use for signing)
	TxnSender   string            `json:"txn_sender,omitempty"`    // Actual transaction sender (for display)
	TxnBytesHex string            `json:"txn_bytes_hex,omitempty"` // Full transaction bytes (TX + msgpack) - server derives what to sign from this
	LsigArgs    map[string]string `json:"lsig_args,omitempty"`     // Runtime args for generic LSigs (name -> hex value)
	LsigSize    int               `json:"lsig_size,omitempty"`     // LSig size hint for foreign transactions (no key on this signer)

	// Passthrough mode field (transaction already signed externally)
	SignedTxnHex string `json:"signed_txn_hex,omitempty"` // Already-signed transaction (msgpack, hex-encoded) - included as-is
}

// SignResponse is the response from Signer after signing
type SignResponse struct {
	Approved        bool     `json:"approved"`                    // True if user approved the request
	Signature       string   `json:"signature,omitempty"`         // Cryptographic signature (ed25519 or DSA lsig)
	LsigBytecode    string   `json:"lsig_bytecode,omitempty"`     // LogicSig bytecode (all lsig types)
	LsigArgsOrdered []string `json:"lsig_args_ordered,omitempty"` // Ordered runtime args (hex), ready for LogicSig.Args
	SignedTxn       string   `json:"signed_txn,omitempty"`        // Complete signed transaction (msgpack, hex-encoded)
	Error           string   `json:"error,omitempty"`
}

// GroupSignRequest is the request payload for the /sign endpoint.
// Contains an array of transactions to be signed as a group.
type GroupSignRequest struct {
	Requests []SignRequest `json:"requests"` // Array of transactions to sign as a group
}

// MutationReport describes modifications made by the server during signing.
// This provides observability for clients to understand what changed.
type MutationReport struct {
	DummiesAdded     int    `json:"dummies_added,omitempty"`     // Number of dummy transactions added for LSig budget
	GroupIDChanged   bool   `json:"group_id_changed,omitempty"`  // True if group ID was computed/recomputed
	FeesModified     []int  `json:"fees_modified,omitempty"`     // Indices of transactions with modified fees (0-based)
	TotalFeesDelta   int    `json:"total_fees_delta,omitempty"`  // Total fee increase in microAlgos (for dummy fees)
	OriginalCount    int    `json:"original_count,omitempty"`    // Number of transactions in original request
	FinalCount       int    `json:"final_count,omitempty"`       // Number of transactions in signed response
	PassthroughCount int    `json:"passthrough_count,omitempty"` // Number of pre-signed transactions included as-is
	ForeignCount     int    `json:"foreign_count,omitempty"`     // Number of foreign transactions (not signed by this signer)
	Reason           string `json:"reason,omitempty"`            // Human-readable reason (e.g., "lsig_budget", "passthrough", "foreign")
}

// GroupSignResponse is the response from the /sign endpoint.
type GroupSignResponse struct {
	Signed    []string        `json:"signed,omitempty"`    // Array of signed transactions (hex-encoded msgpack)
	Mutations *MutationReport `json:"mutations,omitempty"` // Modifications made by server (nil if none)
	Error     string          `json:"error,omitempty"`
}

// GroupPlanResponse is the response from the /plan endpoint.
// Returns the planned group (unsigned transactions with dummies, adjusted fees, group IDs)
// and a mutation report. No keys are touched, no approval flow is triggered.
type GroupPlanResponse struct {
	Transactions []string        `json:"transactions,omitempty"` // TX-prefixed hex-encoded unsigned txns (final group)
	Mutations    *MutationReport `json:"mutations,omitempty"`    // Modifications that would be made by server
	Error        string          `json:"error,omitempty"`
}

// KeyTypeInfo describes an available key type from the /keytypes endpoint
type KeyTypeInfo struct {
	KeyType           string              `json:"key_type"`
	Family            string              `json:"family"`
	DisplayName       string              `json:"display_name"`
	Description       string              `json:"description"`
	RequiresLogicSig  bool                `json:"requires_logicsig"`
	MnemonicWordCount int                 `json:"mnemonic_word_count"`
	MnemonicScheme    string              `json:"mnemonic_scheme"`
	CreationParams    []CreationParamInfo `json:"creation_params"`
	RuntimeArgs       []RuntimeArgInfo    `json:"runtime_args"`
}

// CreationParamInfo describes a parameter required to generate a key of a given type
type CreationParamInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"` // "address", "uint64", "string", "bytes"
	Required    bool   `json:"required"`
	Example     string `json:"example,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Default     string `json:"default,omitempty"`
}

// KeyTypesResponse is the response from the /keytypes endpoint
type KeyTypesResponse struct {
	KeyTypes []KeyTypeInfo `json:"key_types"`
}

// NewSignerClientWithToken creates a new Signer client with authentication token
func NewSignerClientWithToken(baseURL, token string) *SignerClient {
	return &SignerClient{
		BaseURL: baseURL,
		Token:   token,
		Client:  &http.Client{Timeout: 90 * time.Second},
	}
}

// SetToken sets the authentication token
func (c *SignerClient) SetToken(token string) {
	c.Token = token
}

// doRequest performs an HTTP request with authentication
func (c *SignerClient) doRequest(req *http.Request) (*http.Response, error) {
	if c.Token != "" {
		req.Header.Set("Authorization", "aplane "+c.Token)
	}
	return c.Client.Do(req)
}

// Health checks if the Signer service is healthy and responding
func (c *SignerClient) Health() error {
	healthURL := c.BaseURL + "/health"
	// Use a shorter timeout for health checks
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(healthURL)
	if err != nil {
		return fmt.Errorf("signer not responding at %s: %w", c.BaseURL, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != 200 {
		return fmt.Errorf("signer health check failed (status %d)", resp.StatusCode)
	}

	return nil
}

// RuntimeArgInfo describes a runtime argument for generic LogicSig keys.
// Position is implicit: the index in the RuntimeArgs slice corresponds to the TEAL arg index.
type RuntimeArgInfo struct {
	Name        string `json:"name"`                  // Internal name for --lsig-arg (e.g., "preimage")
	Label       string `json:"label"`                 // Human-readable label for UI
	Description string `json:"description,omitempty"` // Help text
	Type        string `json:"type"`                  // "bytes", "string", "uint64"
	Required    bool   `json:"required"`              // If true, must be provided at signing time
	ByteLength  int    `json:"byte_length,omitempty"` // Expected byte length (0 = variable)
}

// KeyInfo represents a key returned from the /keys endpoint
type KeyInfo struct {
	Address       string           `json:"address"`
	PublicKeyHex  string           `json:"public_key_hex"`
	KeyType       string           `json:"key_type"`
	LsigSize      int              `json:"lsig_size,omitempty"` // Total LogicSig size for budget calculation (bytecode + crypto sig)
	IsGenericLsig bool             `json:"is_generic_lsig,omitempty"`
	RuntimeArgs   []RuntimeArgInfo `json:"runtime_args,omitempty"` // Runtime arguments for generic LogicSigs (position = index)
}

// KeysResponse is the response from the /keys endpoint
type KeysResponse struct {
	Count      int       `json:"count"`
	Keys       []KeyInfo `json:"keys"`
	Checksum   string    `json:"-"` // From X-Keys-Checksum header
	CacheValid bool      `json:"-"` // True if 304 Not Modified was returned
	Locked     bool      `json:"-"` // True if signer returned 403 (locked)
}

// RequestGroupSign sends transactions to the /sign endpoint for group signing.
// The server handles dummy transaction creation, fee pooling, and group ID computation.
// Returns the signed transactions (including any dummies added by the server).
func (c *SignerClient) RequestGroupSign(requests []SignRequest) (*GroupSignResponse, error) {
	groupReq := GroupSignRequest{Requests: requests}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	fmt.Println("Waiting for approval from Signer...")

	req, err := http.NewRequest("POST", c.BaseURL+"/sign", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var groupResp GroupSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&groupResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if groupResp.Error != "" {
		return nil, fmt.Errorf("group signing failed: %s", groupResp.Error)
	}

	fmt.Println("Approved by Signer")
	return &groupResp, nil
}

// GetKeys fetches the list of available signing keys from Signer
// If cachedChecksum is provided and matches server's checksum, returns CacheValid=true
func (c *SignerClient) GetKeys(cachedChecksum string) (*KeysResponse, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/keys", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Send cached checksum if available
	if cachedChecksum != "" {
		req.Header.Set("X-Keys-Checksum", cachedChecksum)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			Debug("failed to close response body", "error", err)
		}
	}()

	// Get checksum from response header
	newChecksum := resp.Header.Get("X-Keys-Checksum")

	// Handle 304 Not Modified - cache is valid
	if resp.StatusCode == http.StatusNotModified {
		return &KeysResponse{
			CacheValid: true,
			Checksum:   newChecksum,
		}, nil
	}

	// Handle 403 Forbidden - signer is locked
	if resp.StatusCode == http.StatusForbidden {
		return &KeysResponse{Locked: true}, nil
	}

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var keysResp KeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	keysResp.Checksum = newChecksum
	keysResp.CacheValid = false

	return &keysResp, nil
}

// AdminGenerateRequest is the request payload for POST /admin/generate
type AdminGenerateRequest struct {
	KeyType    string            `json:"key_type"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// AdminGenerateResponse is the response from POST /admin/generate
type AdminGenerateResponse struct {
	Address    string            `json:"address,omitempty"`
	KeyType    string            `json:"key_type,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// AdminDeleteResponse is the response from DELETE /admin/keys
type AdminDeleteResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// AdminGenerate requests key generation from Signer
func (c *SignerClient) AdminGenerate(keyType string, params map[string]string) (*AdminGenerateResponse, error) {
	reqBody := AdminGenerateRequest{
		KeyType:    keyType,
		Parameters: params,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/admin/generate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var genResp AdminGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if genResp.Error != "" {
		return nil, fmt.Errorf("key generation failed: %s", genResp.Error)
	}

	return &genResp, nil
}

// AdminDeleteKey requests key deletion from Signer
func (c *SignerClient) AdminDeleteKey(address string) (*AdminDeleteResponse, error) {
	req, err := http.NewRequest("DELETE", c.BaseURL+"/admin/keys?address="+address, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var delResp AdminDeleteResponse
	if err := json.NewDecoder(resp.Body).Decode(&delResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if delResp.Error != "" {
		return nil, fmt.Errorf("key deletion failed: %s", delResp.Error)
	}

	return &delResp, nil
}

// GetKeyTypes fetches available key types from Signer
func (c *SignerClient) GetKeyTypes() (*KeyTypesResponse, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/keytypes", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get key types: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var ktResp KeyTypesResponse
	if err := json.NewDecoder(resp.Body).Decode(&ktResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &ktResp, nil
}
