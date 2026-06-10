// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerapi defines the HTTP payload types shared between signer
// servers and signer-aware clients.
package signerapi

import (
	"fmt"
)

const maxSignRequestIDLength = 128

// SignRequest is the request payload for Signer signing.
// Three modes are supported (mutually exclusive):
//   - Sign mode: auth_address + txn_bytes_hex (server signs with its key)
//   - Passthrough mode: signed_txn_hex (already signed, included as-is)
//   - Foreign mode: txn_bytes_hex without auth_address (belongs to another signer; context-only)
//
// Passthrough mode requires pre-grouped transactions (group ID already set).
// Foreign mode is accepted on both /plan and /sign. It includes the
// transaction in group building (dummies, fees, group ID) but does not sign
// it. The optional lsig_size hint reserves LSig budget for the foreign
// party's key type.
type SignRequest struct {
	// Sign mode fields (server signs this transaction)
	AuthAddress string            `json:"auth_address,omitempty"`  // Auth address (which key to use for signing)
	TxnSender   string            `json:"txn_sender,omitempty"`    // Advisory display hint; server derives authority from txn bytes
	TxnBytesHex string            `json:"txn_bytes_hex,omitempty"` // Full transaction bytes (TX + msgpack) - server derives what to sign from this
	LsigArgs    map[string]string `json:"lsig_args,omitempty"`     // Runtime args for generic LSigs (name -> hex value)
	LsigSize    int               `json:"lsig_size,omitempty"`     // LSig size hint for foreign transactions (no key on this signer)
	AppCallInfo *AppCallInfo      `json:"app_call_info,omitempty"` // Optional app-call metadata for approval rendering

	// Passthrough mode field (transaction already signed externally)
	SignedTxnHex string `json:"signed_txn_hex,omitempty"` // Already-signed transaction (msgpack, hex-encoded) - included as-is
}

// AppCallInfo carries optional high-level app-call metadata from the caller to
// the signer approval layer. This allows approval prompts to distinguish raw vs
// ABI app calls and, for ABI calls, show the resolved method signature.
type AppCallInfo struct {
	Mode   string `json:"mode,omitempty"`   // "raw" or "abi"
	Method string `json:"method,omitempty"` // ABI method signature when available
}

// SignResponse is the legacy single-transaction response shape.
//
// The HTTP /sign endpoint returns GroupSignResponse. This type is retained for
// source compatibility with older client code.
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
	RequestID string        `json:"request_id,omitempty"` // Optional client-generated ID used to cancel pending manual approval
	Requests  []SignRequest `json:"requests"`             // Array of transactions to sign as a group
}

// CancelSignRequest is the request payload for /sign/cancel.
type CancelSignRequest struct {
	RequestID string `json:"request_id"`
}

// CancelSignResponse is the response payload for /sign/cancel.
type CancelSignResponse struct {
	Success bool            `json:"success"`
	State   SignCancelState `json:"state,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// RequestMode describes the mutually exclusive mode selected by a SignRequest.
type RequestMode string

// SignCancelState describes the result of a /sign/cancel lifecycle transition.
type SignCancelState string

const (
	RequestModeSign        RequestMode = "sign"
	RequestModePassthrough RequestMode = "passthrough"
	RequestModeForeign     RequestMode = "foreign"

	// SignCancelStateCanceled means the request is canceled or a pre-pending
	// cancellation was recorded for that request ID.
	SignCancelStateCanceled SignCancelState = "canceled"

	// SignCancelStateNotFound means no pending request exists for the ID and no
	// pre-pending cancellation was recorded.
	SignCancelStateNotFound SignCancelState = "not_found"
)

// Mode returns the request mode selected by this SignRequest.
func (r SignRequest) Mode() (RequestMode, error) {
	hasPassthrough := r.SignedTxnHex != ""
	hasTxnBytes := r.TxnBytesHex != ""
	hasAuthAddr := r.AuthAddress != ""

	if hasPassthrough && (hasTxnBytes || hasAuthAddr) {
		return "", fmt.Errorf("cannot specify both sign fields (auth_address/txn_bytes_hex) and passthrough field (signed_txn_hex)")
	}
	if hasPassthrough {
		return RequestModePassthrough, nil
	}
	if hasTxnBytes && hasAuthAddr {
		return RequestModeSign, nil
	}
	if hasTxnBytes && !hasAuthAddr {
		return RequestModeForeign, nil
	}
	if hasAuthAddr && !hasTxnBytes {
		return "", fmt.Errorf("txn_bytes_hex is required for sign mode")
	}
	return "", fmt.Errorf("must specify either sign fields (auth_address + txn_bytes_hex), foreign fields (txn_bytes_hex), or passthrough field (signed_txn_hex)")
}

// Validate checks that the request uses exactly one supported request mode.
func (r SignRequest) Validate() error {
	_, err := r.Mode()
	return err
}

// Validate checks that all contained requests use a supported request mode.
func (r GroupSignRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.Requests) == 0 {
		return fmt.Errorf("requests array is empty")
	}

	signCount := 0
	passthroughCount := 0
	foreignCount := 0
	for i, req := range r.Requests {
		mode, err := req.Mode()
		if err != nil {
			return fmt.Errorf("transaction %d: %w", i+1, err)
		}
		switch mode {
		case RequestModeSign:
			signCount++
		case RequestModePassthrough:
			passthroughCount++
		case RequestModeForeign:
			foreignCount++
		}
	}

	if passthroughCount > 0 && foreignCount > 0 {
		return fmt.Errorf("cannot mix passthrough and foreign transactions: passthrough requires pre-grouped, foreign requires server-computed group ID")
	}
	if signCount == 0 && foreignCount > 0 {
		return fmt.Errorf("no signable transactions: all entries are foreign. Build and submit this group locally instead of using apsigner")
	}
	return nil
}

// Validate checks that the cancel request names a concrete sign request.
func (r CancelSignRequest) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	return validateSignRequestID(r.RequestID)
}

func validateSignRequestID(id string) error {
	if id == "" {
		return nil
	}
	if len(id) > maxSignRequestIDLength {
		return fmt.Errorf("request_id is too long")
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == ':' {
			continue
		}
		return fmt.Errorf("request_id contains invalid character %q", ch)
	}
	return nil
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

// GroupSimulateResponse is the response from the /simulate endpoint.
// The signer signs internally, submits the signed group to algod simulate, and
// returns only unsigned planned transactions plus diagnostic output. Signed
// transaction bytes are intentionally not part of this contract.
type GroupSimulateResponse struct {
	TxIDs        []string        `json:"tx_ids,omitempty"`       // Transaction IDs for the simulated group
	Transactions []string        `json:"transactions,omitempty"` // TX-prefixed hex-encoded unsigned txns (final group)
	Mutations    *MutationReport `json:"mutations,omitempty"`    // Modifications made by server planning
	Output       string          `json:"output,omitempty"`       // Human-readable simulation report
	Failed       bool            `json:"failed,omitempty"`       // True when algod simulate returned an execution failure
	Error        string          `json:"error,omitempty"`
}

// ErrorResponse is the standard HTTP error body for non-2xx signer responses.
// Code carries a stable machine-readable classification (see error_codes.go);
// clients should branch on Code, never on Error message text. Code may be
// empty when the failure has no specific classification.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// HealthResponse is the response from the /health endpoint.
type HealthResponse struct {
	Status          string `json:"status"`
	Service         string `json:"service"`
	SignerLocked    bool   `json:"signer_locked"`
	ReadyForSigning bool   `json:"ready_for_signing"`
	SSHEnabled      bool   `json:"ssh_enabled"`
	IPCEnabled      bool   `json:"ipc_enabled"`
}

// StatusResponse is the response from the /status endpoint.
type StatusResponse struct {
	IdentityID          string `json:"identity_id"`
	NodeRole            string `json:"node_role,omitempty"`
	State               string `json:"state"`
	SignerLocked        bool   `json:"signer_locked"`
	ReadyForSigning     bool   `json:"ready_for_signing"`
	KeyCount            int    `json:"key_count"`
	KeysetRevision      uint64 `json:"keyset_revision"`
	ApprovalWaitSeconds int64  `json:"approval_wait_seconds,omitempty"`
}

// KeyTypeInfo describes an available key type from the /keytypes endpoint.
type KeyTypeInfo struct {
	KeyType           string              `json:"key_type"`
	Family            string              `json:"family"`
	DisplayName       string              `json:"display_name"`
	Description       string              `json:"description"`
	RequiresLogicSig  bool                `json:"requires_logicsig"`
	MnemonicWordCount int                 `json:"mnemonic_word_count"`
	MnemonicImport    bool                `json:"mnemonic_import"`
	MnemonicScheme    string              `json:"mnemonic_scheme"`
	CreationParams    []CreationParamInfo `json:"creation_params"`
	RuntimeArgs       []RuntimeArgInfo    `json:"runtime_args"`
}

// CreationParamInfo describes a parameter required to generate a key of a given type.
type CreationParamInfo struct {
	Name        string          `json:"name"`
	Label       string          `json:"label"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type"` // "address", "address[]", "uint64", "string", "bytes"
	Required    bool            `json:"required"`
	MaxLength   int             `json:"max_length,omitempty"`
	InputModes  []InputModeInfo `json:"input_modes,omitempty"`
	Options     []string        `json:"options,omitempty"`
	MinItems    int             `json:"min_items,omitempty"`
	MaxItems    int             `json:"max_items,omitempty"`
	Example     string          `json:"example,omitempty"`
	Placeholder string          `json:"placeholder,omitempty"`
	Min         *uint64         `json:"min,omitempty"`
	Max         *uint64         `json:"max,omitempty"`
	Default     string          `json:"default,omitempty"`
}

// InputModeInfo describes an alternate UI input mode for a creation parameter.
type InputModeInfo struct {
	Name       string `json:"name"`
	Label      string `json:"label,omitempty"`
	Transform  string `json:"transform,omitempty"`
	ByteLength int    `json:"byte_length,omitempty"`
	InputType  string `json:"input_type,omitempty"`
}

// RuntimeArgInfo is runtime-argument metadata exposed from /keytypes.
type RuntimeArgInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "address", "uint64", "string", "bytes"
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	ByteLength  int    `json:"byte_length,omitempty"`
}

// SigningArgInfo is the key-file-owned signing-argument metadata exposed from /keys.
type SigningArgInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "address", "uint64", "string", "bytes"
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	ByteLength  int    `json:"byte_length,omitempty"`
}

// KeyTypesResponse is the response from the /keytypes endpoint.
type KeyTypesResponse struct {
	KeyTypes []KeyTypeInfo `json:"key_types"`
}

// KeyInfo represents a key returned from the /keys endpoint.
type KeyInfo struct {
	Address                  string            `json:"address"`
	PublicKeyHex             string            `json:"public_key_hex"`
	KeyType                  string            `json:"key_type"`
	LsigSize                 int               `json:"lsig_size,omitempty"` // Total LogicSig size for budget calculation (bytecode + crypto sig)
	IsGenericLsig            bool              `json:"is_generic_lsig,omitempty"`
	IsComponentKey           bool              `json:"is_component_key,omitempty"`
	IsSpendingAccount        *bool             `json:"is_spending_account,omitempty"`
	SigningArgs              []SigningArgInfo  `json:"signing_args,omitempty"` // Key-file signing arguments for LogicSigs (position = index)
	Parameters               map[string]string `json:"parameters,omitempty"`
	TemplateProvenanceStatus string            `json:"template_provenance_status,omitempty"`
	TemplateProvenanceNote   string            `json:"template_provenance_note,omitempty"`
}

// KeysResponse is the response from the /keys endpoint.
type KeysResponse struct {
	Count int       `json:"count"`
	Keys  []KeyInfo `json:"keys"`
}

// AdminGenerateRequest is the request payload for POST /admin/generate.
type AdminGenerateRequest struct {
	KeyType    string            `json:"key_type"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// AdminGenerateResponse is the response from POST /admin/generate.
type AdminGenerateResponse struct {
	Address           string            `json:"address,omitempty"`
	PublicKeyHex      string            `json:"public_key_hex,omitempty"`
	KeyType           string            `json:"key_type,omitempty"`
	IsComponentKey    bool              `json:"is_component_key,omitempty"`
	IsSpendingAccount *bool             `json:"is_spending_account,omitempty"`
	Parameters        map[string]string `json:"parameters,omitempty"`
	Error             string            `json:"error,omitempty"`
}

// AdminDeleteResponse is the response from DELETE /admin/keys.
type AdminDeleteResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// SentryReferenceCandidate is public sentry metadata synced from client
// endpoint discovery into a signer identity's generation reference catalog.
type SentryReferenceCandidate struct {
	EndpointAlias string `json:"endpoint_alias"`
	ComponentKey  string `json:"component_key"`
	KeyType       string `json:"key_type"`
	PublicKeyHex  string `json:"public_key_hex"`
	LastSeenAt    string `json:"last_seen_at,omitempty"`
}

// AdminSyncSentryReferencesRequest is the request payload for
// POST /admin/sentries/sync.
type AdminSyncSentryReferencesRequest struct {
	Candidates []SentryReferenceCandidate `json:"candidates"`
}

// SyncedSentryReferenceInfo describes a signer-local reference after sync.
type SyncedSentryReferenceInfo struct {
	Name          string `json:"name"`
	Source        string `json:"source"`
	EndpointAlias string `json:"endpoint_alias,omitempty"`
	ComponentKey  string `json:"component_key"`
	KeyType       string `json:"key_type"`
	PublicKeyHex  string `json:"public_key_hex"`
	LastSeenAt    string `json:"last_seen_at,omitempty"`
	SyncedAt      string `json:"synced_at,omitempty"`
}

// AdminSyncSentryReferencesResponse is the response payload for
// POST /admin/sentries/sync.
type AdminSyncSentryReferencesResponse struct {
	Added   int                         `json:"added"`
	Updated int                         `json:"updated"`
	Removed int                         `json:"removed"`
	Count   int                         `json:"count"`
	Records []SyncedSentryReferenceInfo `json:"records,omitempty"`
	Error   string                      `json:"error,omitempty"`
}
