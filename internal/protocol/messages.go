// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package protocol defines the line-delimited JSON admin protocol message
// types shared between apsigner (server) and apadmin/TUI (client) over IPC
// and SSH admin transport.
// This is the single source of truth for the wire protocol.
package protocol

type MessageKind string

const (
	MessageKindRequest      MessageKind = "request"
	MessageKindResponse     MessageKind = "response"
	MessageKindNotification MessageKind = "notification"
)

// Admin protocol message type constants
const (
	// Authentication message types (sent before any other messages)
	MsgTypeAuthRequired = "auth_required"
	MsgTypeAuth         = "auth"
	MsgTypeAuthResult   = "auth_result"

	// Signer state message types
	MsgTypeUnlock                = "unlock"
	MsgTypeUnlockResult          = "unlock_result"
	MsgTypeLockIdentity          = "lock_identity"
	MsgTypeLockIdentityResult    = "lock_identity_result"
	MsgTypeInitializeStore       = "initialize_store"
	MsgTypeInitializeStoreResult = "initialize_store_result"
	MsgTypeChangeStorePass       = "change_store_passphrase"
	MsgTypeChangeStorePassResult = "change_store_passphrase_result"
	MsgTypeBackup                = "backup"
	MsgTypeBackupResult          = "backup_result"
	MsgTypeListBackups           = "list_backups"
	MsgTypeBackupsList           = "backups_list"
	MsgTypeDeleteBackup          = "delete_backup"
	MsgTypeDeleteBackupResult    = "delete_backup_result"
	MsgTypePreviewRestore        = "preview_restore"
	MsgTypeRestorePreview        = "restore_preview"
	MsgTypeRestoreBackup         = "restore_backup"
	MsgTypeRestoreBackupResult   = "restore_backup_result"
	MsgTypeSignRequest           = "sign_request"
	MsgTypeSignRequestCanceled   = "sign_request_canceled"
	MsgTypeSignResponse          = "sign_response"
	MsgTypeStatus                = "status"
	MsgTypeError                 = "error"

	// Token provisioning message types (SSH-based token request approval)
	MsgTypeTokenProvisioningRequest  = "token_provisioning_request"
	MsgTypeTokenProvisioningResponse = "token_provisioning_response"

	// Token revocation message types
	MsgTypeRevokeToken       = "revoke_token"
	MsgTypeRevokeTokenResult = "revoke_token_result"

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

	// Template library and key type metadata message types
	MsgTypeListLibraryTemplates          = "list_library_templates"
	MsgTypeLibraryTemplates              = "library_templates"
	MsgTypeInstallLibraryTemplate        = "install_library_template"
	MsgTypeInstallLibraryTemplateResult  = "install_library_template_result"
	MsgTypeListInstalledTemplates        = "list_installed_templates"
	MsgTypeInstalledTemplates            = "installed_templates"
	MsgTypeShowInstalledTemplate         = "show_installed_template"
	MsgTypeShowInstalledTemplateResult   = "show_installed_template_result"
	MsgTypeShowLibraryTemplate           = "show_library_template"
	MsgTypeShowLibraryTemplateResult     = "show_library_template_result"
	MsgTypeImportInstalledTemplate       = "import_installed_template"
	MsgTypeImportInstalledTemplateResult = "import_installed_template_result"
	MsgTypeRemoveInstalledTemplate       = "remove_installed_template"
	MsgTypeRemoveInstalledTemplateResult = "remove_installed_template_result"
	MsgTypeActivateKeyType               = "activate_key_type"
	MsgTypeActivateKeyTypeResult         = "activate_key_type_result"
	MsgTypeDeactivateKeyType             = "deactivate_key_type"
	MsgTypeDeactivateKeyTypeResult       = "deactivate_key_type_result"
	MsgTypeListKeyTypes                  = "list_key_types"
	MsgTypeKeyTypes                      = "key_types"

	// Server-initiated notification message types
	MsgTypeKeysChanged  = "keys_changed"  // Sent when keys are reloaded
	MsgTypeSignerLocked = "signer_locked" // Sent when signer locks

	// Admin settings message types
	MsgTypeGetAdminSettings          = "get_admin_settings"           // Client → server: request current settings
	MsgTypeAdminSettings             = "admin_settings"               // Server → client: current settings
	MsgTypeUpdateAdminSetting        = "update_admin_setting"         // Client → server: change a setting
	MsgTypeUpdateAdminSettingResult  = "update_admin_setting_result"  // Server → client: result
	MsgTypeGetPolicySettings         = "get_policy_settings"          // Client → server: request current policy settings
	MsgTypePolicySettings            = "policy_settings"              // Server → client: current policy settings
	MsgTypeGetPolicySnapshot         = "get_policy_snapshot"          // Client → server: request active read-only policy snapshot
	MsgTypePolicySnapshot            = "policy_snapshot"              // Server → client: active read-only policy snapshot
	MsgTypeReplacePolicy             = "replace_policy"               // Client → server: wholesale replace policy.yaml
	MsgTypeReplacePolicyResult       = "replace_policy_result"        // Server → client: replacement result and active snapshot
	MsgTypeValidatePolicy            = "validate_policy"              // Client → server: validate policy YAML without writing
	MsgTypeValidatePolicyResult      = "validate_policy_result"       // Server → client: validation result
	MsgTypeUpdatePolicySetting       = "update_policy_setting"        // Client → server: change a policy setting
	MsgTypeUpdatePolicySettingResult = "update_policy_setting_result" // Server → client: result
	MsgTypeUpdatePolicyASAAmounts    = "update_policy_asa_amounts"    // Client → server: atomically change transfer guards
	MsgTypeUpdatePolicyASAResult     = "update_policy_asa_result"     // Server → client: result
	MsgTypeSearchASAMetadata         = "search_asa_metadata"          // Client → server: search signer ASA metadata cache
	MsgTypeASAMetadataResults        = "asa_metadata_results"         // Server → client: ASA metadata search result
	MsgTypeResolveASAMetadata        = "resolve_asa_metadata"         // Client → server: resolve ASA metadata by numeric ID
	MsgTypeASAMetadataResult         = "asa_metadata_result"          // Server → client: ASA metadata resolution result

	// Client displacement message types (for single-client IPC enforcement)
	MsgTypeClientExists    = "client_exists"    // Server → new client: another client is connected
	MsgTypeDisplaceConfirm = "displace_confirm" // New client → server: proceed with displacement
	MsgTypeDisplaced       = "displaced"        // Server → old client: you've been displaced
)

// BaseMessage is the base structure for all admin protocol messages.
type BaseMessage struct {
	Kind MessageKind `json:"kind,omitempty"`
	Type string      `json:"type"`
	ID   string      `json:"id"` // Unique request ID for correlation
}

// AuthRequiredMessage is sent by signer when a client connects
// Client must respond with AuthMessage before any other operations
type AuthRequiredMessage struct {
	BaseMessage
}

// AuthMessage is sent by apadmin to authenticate the IPC session.
// IdentityID is optional; if omitted, the server binds the session to
// the current product identity (backward compatible with older clients).
type AuthMessage struct {
	BaseMessage
	Passphrase SensitiveBytes `json:"passphrase"`
	IdentityID string         `json:"identity_id,omitempty"`
}

// AuthResultMessage is sent back after an authentication attempt
type AuthResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

// UnlockMessage is sent by apadmin to unlock the signer
type UnlockMessage struct {
	BaseMessage
	Passphrase SensitiveBytes `json:"passphrase"`
}

// UnlockResultMessage is sent back after an unlock attempt
type UnlockResultMessage struct {
	BaseMessage
	Success  bool   `json:"success"`
	KeyCount int    `json:"key_count,omitempty"`
	Code     string `json:"code,omitempty"`
	Error    string `json:"error,omitempty"`
}

// LockIdentityMessage requests an explicit lock of the currently bound identity.
type LockIdentityMessage struct {
	BaseMessage
	Reason string `json:"reason,omitempty"`
}

// LockIdentityResultMessage is the result of an explicit identity lock request.
type LockIdentityResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

type InitializeStoreMessage struct {
	BaseMessage
	Passphrase SensitiveBytes `json:"passphrase"`
}

type InitializeStoreResultMessage struct {
	BaseMessage
	Success       bool   `json:"success"`
	MetadataDir   string `json:"metadata_dir,omitempty"`
	HelperWarning string `json:"helper_warning,omitempty"`
	Code          string `json:"code,omitempty"`
	Error         string `json:"error,omitempty"`
}

type ChangeStorePassphraseMessage struct {
	BaseMessage
	CurrentPassphrase SensitiveBytes `json:"current_passphrase"`
	NewPassphrase     SensitiveBytes `json:"new_passphrase"`
}

type ChangeStorePassphraseResultMessage struct {
	BaseMessage
	Success                  bool   `json:"success"`
	KeysMigrated             int    `json:"keys_migrated,omitempty"`
	TemplatesMigrated        int    `json:"templates_migrated,omitempty"`
	PolicySidecarsMigrated   int    `json:"policy_sidecars_migrated,omitempty"`
	NodeRoleSidecarsMigrated int    `json:"node_role_sidecars_migrated,omitempty"`
	Code                     string `json:"code,omitempty"`
	Error                    string `json:"error,omitempty"`
}

// BackupMessage requests signer-managed creation of a portable key backup for
// the currently bound identity. The export passphrase protects the resulting
// .apb payloads inside the archive.
type BackupMessage struct {
	BaseMessage
	ExportPassphrase SensitiveBytes `json:"export_passphrase"`
	Addresses        []string       `json:"addresses,omitempty"`
}

// BackupResultMessage is the result of a signer-managed backup request.
type BackupResultMessage struct {
	BaseMessage
	Success         bool     `json:"success"`
	ArchivePath     string   `json:"archive_path,omitempty"`
	ArchiveChecksum string   `json:"archive_checksum,omitempty"`
	ArchiveSize     int64    `json:"archive_size,omitempty"`
	KeyCount        int      `json:"key_count,omitempty"`
	Addresses       []string `json:"addresses,omitempty"`
	Verified        bool     `json:"verified,omitempty"`
	Code            string   `json:"code,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// ListBackupsMessage requests managed backup archives for the bound identity.
type ListBackupsMessage struct {
	BaseMessage
}

type BackupInfo struct {
	Path      string `json:"path"`
	FileName  string `json:"file_name"`
	CreatedAt int64  `json:"created_at,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Checksum  string `json:"checksum,omitempty"`
	Verified  bool   `json:"verified,omitempty"`
}

type BackupsListMessage struct {
	BaseMessage
	Backups []BackupInfo `json:"backups,omitempty"`
	Code    string       `json:"code,omitempty"`
	Error   string       `json:"error,omitempty"`
}

type DeleteBackupMessage struct {
	BaseMessage
	ArchivePath string `json:"archive_path"`
}

type DeleteBackupResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

type PreviewRestoreMessage struct {
	BaseMessage
	ArchivePath      string         `json:"archive_path"`
	ExportPassphrase SensitiveBytes `json:"export_passphrase"`
}

type RestoreKeyInfo struct {
	Address       string `json:"address"`
	KeyType       string `json:"key_type,omitempty"`
	AlreadyExists bool   `json:"already_exists,omitempty"`
	HasTemplate   bool   `json:"has_template,omitempty"`
	TemplateType  string `json:"template_type,omitempty"`
	Error         string `json:"error,omitempty"`
}

type RestoreError struct {
	Address string `json:"address,omitempty"`
	Error   string `json:"error"`
}

type RestoreWarning struct {
	Address string `json:"address,omitempty"`
	KeyType string `json:"key_type,omitempty"`
	Warning string `json:"warning"`
}

type RestorePreviewMessage struct {
	BaseMessage
	ArchivePath string           `json:"archive_path,omitempty"`
	Keys        []RestoreKeyInfo `json:"keys,omitempty"`
	Errors      []RestoreError   `json:"errors,omitempty"`
	Code        string           `json:"code,omitempty"`
	Error       string           `json:"error,omitempty"`
}

type RestoreBackupMessage struct {
	BaseMessage
	ArchivePath      string         `json:"archive_path"`
	Addresses        []string       `json:"addresses,omitempty"`
	Overwrite        bool           `json:"overwrite,omitempty"`
	ExportPassphrase SensitiveBytes `json:"export_passphrase"`
}

type RestoreBackupResultMessage struct {
	BaseMessage
	ArchivePath string           `json:"archive_path,omitempty"`
	Success     bool             `json:"success"`
	Restored    []RestoreKeyInfo `json:"restored,omitempty"`
	Skipped     []RestoreKeyInfo `json:"skipped,omitempty"`
	Errors      []RestoreError   `json:"errors,omitempty"`
	Warnings    []RestoreWarning `json:"warnings,omitempty"`
	KeyCount    int              `json:"key_count,omitempty"`
	Code        string           `json:"code,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// PolicyViolation represents a dangerous transaction field detected by the policy engine
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

// SignRequestCanceledMessage is sent to apadmin when a pending signing request
// is no longer actionable, for example because the HTTP requester disconnected
// or apsigner's approval wait timed out.
type SignRequestCanceledMessage struct {
	BaseMessage
	Reason string `json:"reason,omitempty"`
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
	IdentityID     string `json:"identity_id"`     // Identity requesting token (typically the current product identity)
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

// RevokeTokenMessage is sent by apadmin to revoke the current API token
type RevokeTokenMessage struct {
	BaseMessage
}

// RevokeTokenResultMessage is the response to a token revocation request
type RevokeTokenResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
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
	Code  string `json:"code,omitempty"`
	Error string `json:"error"`
}

// ListKeysMessage requests the list of keys from signer
type ListKeysMessage struct {
	BaseMessage
}

// KeyInfo represents information about a single key in the wire protocol
type KeyInfo struct {
	Address                  string `json:"address"`
	KeyType                  string `json:"key_type"` // Full versioned type: "ed25519", "aplane.falcon1024.v1", etc.
	Name                     string `json:"name,omitempty"`
	TemplateProvenanceStatus string `json:"template_provenance_status,omitempty"`
	TemplateProvenanceNote   string `json:"template_provenance_note,omitempty"`
}

// KeysListMessage contains the list of keys from signer
type KeysListMessage struct {
	BaseMessage
	Keys []KeyInfo `json:"keys"`
}

// GenerateKeyMessage requests generation of a new key
type GenerateKeyMessage struct {
	BaseMessage
	KeyType    string            `json:"key_type"` // Versioned key type: "ed25519", "aplane.falcon1024.v1", "aplane.timed-whitelist.v1", etc.
	Name       string            `json:"name,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"` // Template parameters (for generic lsigs like timed-whitelist)
}

// GenerateResultMessage contains the result of key generation
type GenerateResultMessage struct {
	BaseMessage
	Success    bool              `json:"success"`
	Address    string            `json:"address,omitempty"`
	KeyType    string            `json:"key_type,omitempty"` // Full versioned type: "ed25519", "aplane.falcon1024.v1", etc.
	Mnemonic   string            `json:"mnemonic,omitempty"` // Legacy compatibility field; current responses omit it.
	WordCount  int               `json:"word_count,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"` // Creation parameters needed for address re-derivation
	Code       string            `json:"code,omitempty"`
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
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ExportKeyMessage requests export of a key's mnemonic. Current servers deny
// this request on every admin transport.
type ExportKeyMessage struct {
	BaseMessage
	Address    string         `json:"address"`
	Passphrase SensitiveBytes `json:"passphrase"` // Required to verify user identity before export
}

// ExportResultMessage is retained for legacy decode compatibility. Current
// servers return an error instead of this response.
type ExportResultMessage struct {
	BaseMessage
	Success    bool              `json:"success"`
	Address    string            `json:"address,omitempty"`
	KeyType    string            `json:"key_type,omitempty"` // Full versioned type: "ed25519", "aplane.falcon1024.v1", etc.
	Mnemonic   string            `json:"mnemonic,omitempty"` // Legacy compatibility field; current responses omit it.
	WordCount  int               `json:"word_count,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"` // Creation parameters needed for address re-derivation
	Code       string            `json:"code,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// ImportKeyMessage requests import of a key from mnemonic
type ImportKeyMessage struct {
	BaseMessage
	KeyType    string            `json:"key_type"` // Versioned key type: "ed25519", "aplane.falcon1024.v1", etc.
	Mnemonic   string            `json:"mnemonic"` // The recovery phrase
	Parameters map[string]string `json:"parameters,omitempty"`
}

// ImportResultMessage contains the result of key import
type ImportResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Address string `json:"address,omitempty"`
	KeyType string `json:"key_type,omitempty"`
	Code    string `json:"code,omitempty"`
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
	Success                  bool              `json:"success"`
	Address                  string            `json:"address,omitempty"`
	KeyType                  string            `json:"key_type,omitempty"`
	PublicKeyHex             string            `json:"public_key_hex,omitempty"`
	Parameters               map[string]string `json:"parameters,omitempty"`   // For generic LogicSigs: recipients, unlock_round, etc.
	DisplayTEAL              string            `json:"display_teal,omitempty"` // TEAL source for generic LogicSigs (actual compiled source)
	TemplateProvenanceStatus string            `json:"template_provenance_status,omitempty"`
	TemplateProvenanceNote   string            `json:"template_provenance_note,omitempty"`
	Code                     string            `json:"code,omitempty"`
	Error                    string            `json:"error,omitempty"`
}

type TemplateParamInfo struct {
	Name        string          `json:"name"`
	Label       string          `json:"label"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type"`
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

type InputModeInfo struct {
	Name       string `json:"name"`
	Label      string `json:"label,omitempty"`
	Transform  string `json:"transform,omitempty"`
	ByteLength int    `json:"byte_length,omitempty"`
	InputType  string `json:"input_type,omitempty"`
}

type TemplateArgInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	ByteLength  int    `json:"byte_length,omitempty"`
}

// TemplateType fields use stable wire values: "generic", "composed", or
// "compiled_provider". These are projections of internal key type state
// sources, not on-disk record source literals.
type LibraryTemplateInfo struct {
	KeyType      string              `json:"key_type,omitempty"`
	TemplateType string              `json:"template_type,omitempty"`
	DisplayName  string              `json:"display_name,omitempty"`
	Description  string              `json:"description,omitempty"`
	SourcePath   string              `json:"source_path,omitempty"`
	FileName     string              `json:"file_name,omitempty"`
	Parameters   []TemplateParamInfo `json:"parameters,omitempty"`
	RuntimeArgs  []TemplateArgInfo   `json:"runtime_args,omitempty"`
	Installed    bool                `json:"installed"`
	Enabled      bool                `json:"enabled,omitempty"`
	Conflict     string              `json:"conflict,omitempty"`
	Invalid      string              `json:"invalid,omitempty"`
}

type ListLibraryTemplatesMessage struct {
	BaseMessage
}

type LibraryTemplatesMessage struct {
	BaseMessage
	Templates []LibraryTemplateInfo `json:"templates"`
	Code      string                `json:"code,omitempty"`
	Error     string                `json:"error,omitempty"`
}

type InstallLibraryTemplateMessage struct {
	BaseMessage
	KeyType      string `json:"key_type"`
	TemplateType string `json:"template_type"`
}

type InstallLibraryTemplateResultMessage struct {
	BaseMessage
	Success       bool   `json:"success"`
	KeyType       string `json:"key_type,omitempty"`
	TemplateType  string `json:"template_type,omitempty"`
	AlreadyExists bool   `json:"already_exists,omitempty"`
	Code          string `json:"code,omitempty"`
	Error         string `json:"error,omitempty"`
}

type InstalledTemplateInfo struct {
	KeyType      string `json:"key_type"`
	TemplateType string `json:"template_type"`
	Size         int64  `json:"size,omitempty"`
	Enabled      bool   `json:"enabled"`
}

type ListInstalledTemplatesMessage struct {
	BaseMessage
}

type InstalledTemplatesMessage struct {
	BaseMessage
	Templates []InstalledTemplateInfo `json:"templates"`
	Code      string                  `json:"code,omitempty"`
	Error     string                  `json:"error,omitempty"`
}

type ShowInstalledTemplateMessage struct {
	BaseMessage
	KeyType string `json:"key_type"`
}

type ShowInstalledTemplateResultMessage struct {
	BaseMessage
	Success      bool           `json:"success"`
	KeyType      string         `json:"key_type,omitempty"`
	TemplateType string         `json:"template_type,omitempty"`
	TemplateYAML SensitiveBytes `json:"template_yaml,omitempty"`
	Code         string         `json:"code,omitempty"`
	Error        string         `json:"error,omitempty"`
}

// ShowLibraryTemplateMessage requests the plaintext YAML for a library entry.
// Library YAMLs are unencrypted on disk; no master key is required.
type ShowLibraryTemplateMessage struct {
	BaseMessage
	KeyType      string `json:"key_type"`
	TemplateType string `json:"template_type"`
}

type ShowLibraryTemplateResultMessage struct {
	BaseMessage
	Success       bool           `json:"success"`
	KeyType       string         `json:"key_type,omitempty"`
	TemplateType  string         `json:"template_type,omitempty"`
	SourcePath    string         `json:"source_path,omitempty"`
	SourceSHA256  string         `json:"source_sha256,omitempty"`
	SourceModTime int64          `json:"source_mtime,omitempty"`
	TemplateYAML  SensitiveBytes `json:"template_yaml,omitempty"`
	Code          string         `json:"code,omitempty"`
	Error         string         `json:"error,omitempty"`
}

type ImportInstalledTemplateMessage struct {
	BaseMessage
	TemplateYAML SensitiveBytes `json:"template_yaml"`
}

type ImportInstalledTemplateResultMessage struct {
	BaseMessage
	Success       bool   `json:"success"`
	KeyType       string `json:"key_type,omitempty"`
	TemplateType  string `json:"template_type,omitempty"`
	AlreadyExists bool   `json:"already_exists,omitempty"`
	Code          string `json:"code,omitempty"`
	Error         string `json:"error,omitempty"`
}

type RemoveInstalledTemplateMessage struct {
	BaseMessage
	KeyType string `json:"key_type"`
}

type RemoveInstalledTemplateResultMessage struct {
	BaseMessage
	Success      bool   `json:"success"`
	KeyType      string `json:"key_type,omitempty"`
	TemplateType string `json:"template_type,omitempty"`
	Removed      bool   `json:"removed,omitempty"`
	Code         string `json:"code,omitempty"`
	Error        string `json:"error,omitempty"`
}

type ActivateKeyTypeMessage struct {
	BaseMessage
	KeyType string `json:"key_type"`
}

type ActivateKeyTypeResultMessage struct {
	BaseMessage
	Success       bool   `json:"success"`
	KeyType       string `json:"key_type,omitempty"`
	AlreadyExists bool   `json:"already_exists,omitempty"`
	Code          string `json:"code,omitempty"`
	Error         string `json:"error,omitempty"`
}

type DeactivateKeyTypeMessage struct {
	BaseMessage
	KeyType string `json:"key_type"`
}

type DeactivateKeyTypeResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	KeyType string `json:"key_type,omitempty"`
	Removed bool   `json:"removed,omitempty"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

type KeyTypeInfo struct {
	KeyType           string              `json:"key_type"`
	Family            string              `json:"family"`
	DisplayName       string              `json:"display_name"`
	Description       string              `json:"description"`
	RequiresLogicSig  bool                `json:"requires_logicsig"`
	MnemonicWordCount int                 `json:"mnemonic_word_count"`
	MnemonicImport    bool                `json:"mnemonic_import"`
	MnemonicScheme    string              `json:"mnemonic_scheme"`
	CreationParams    []TemplateParamInfo `json:"creation_params"`
	RuntimeArgs       []TemplateArgInfo   `json:"runtime_args"`
}

type ListKeyTypesMessage struct {
	BaseMessage
}

type KeyTypesMessage struct {
	BaseMessage
	KeyTypes []KeyTypeInfo `json:"key_types"`
	Code     string        `json:"code,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// KeysChangedMessage is sent by the server to notify clients that the key list has changed
type KeysChangedMessage struct {
	BaseMessage
	KeyCount int `json:"key_count"` // Number of keys after reload
}

// SignerLockedMessage is sent by the server to notify clients that the signer
// has locked. Client should transition to the unlock screen.
type SignerLockedMessage struct {
	BaseMessage
	Reason string `json:"reason"` // Why the signer locked.
}

// GetAdminSettingsMessage requests the current admin settings from the server.
type GetAdminSettingsMessage struct {
	BaseMessage
}

// AdminSettingsMessage contains the current admin settings.
type AdminSettingsMessage struct {
	BaseMessage
	UserAutoApprove      bool   `json:"user_auto_approve"`
	LockOnDisconnect     bool   `json:"lock_on_disconnect"`
	PassphraseTimeout    string `json:"passphrase_timeout"`
	PassphraseMethod     string `json:"passphrase_method"`
	NodeRole             string `json:"node_role,omitempty"`
	SSHEnabled           bool   `json:"ssh_enabled"`
	SSHListenAddress     string `json:"ssh_listen_address,omitempty"`
	SSHPort              int    `json:"ssh_port,omitempty"`
	SSHFingerprint       string `json:"ssh_fingerprint,omitempty"`
	SSHClients           int    `json:"ssh_clients"`
	SignerPort           int    `json:"signer_port"`
	TEALCompileNet       string `json:"teal_compile_network"`
	EndpointAdvertiseURL string `json:"endpoint_advertise_url,omitempty"`
	Theme                string `json:"theme"`
}

// UpdateAdminSettingMessage requests a change to a single admin setting.
type UpdateAdminSettingMessage struct {
	BaseMessage
	Key   string `json:"key"`   // Setting name (e.g. "user_auto_approve")
	Value string `json:"value"` // New value (e.g. "true", "30m")
}

// UpdateAdminSettingResultMessage is the response to an admin setting change.
type UpdateAdminSettingResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Key     string `json:"key"`
	Value   string `json:"value,omitempty"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

// GetPolicySettingsMessage requests the current policy settings from the server.
type GetPolicySettingsMessage struct {
	BaseMessage
}

// PolicySettingsMessage contains the current signer policy settings.
type PolicySettingsMessage struct {
	BaseMessage
	RejectForeignRekey          bool                         `json:"reject_foreign_rekey"`
	RejectCloseRemainder        bool                         `json:"reject_close_remainder"`
	RejectAssetClose            bool                         `json:"reject_asset_close"`
	RejectClawback              bool                         `json:"reject_clawback"`
	AlwaysReviewWarnings        bool                         `json:"always_review_warnings"`
	AutoApproveSelfNoOpTransfer bool                         `json:"auto_approve_self_noop_transfer"`
	MaxFeeMicroAlgos            string                       `json:"max_fee_microalgos"`
	ReviewAlgoPayments          map[string]string            `json:"review_algo_payments,omitempty"`
	MaxAlgoPayments             map[string]string            `json:"max_algo_payments,omitempty"`
	PolicyNetworks              []string                     `json:"policy_networks"`
	ReviewASAAmounts            map[string]string            `json:"review_asa_amounts,omitempty"`
	MaxASAAmounts               map[string]string            `json:"max_asa_amounts,omitempty"`
	PolicyASAMetadata           map[string][]ASAMetadataInfo `json:"policy_asa_metadata,omitempty"`
	MaxASAAmountsMainnet        string                       `json:"max_asa_amounts_mainnet,omitempty"`
	MaxASAAmountsTestnet        string                       `json:"max_asa_amounts_testnet,omitempty"`
	MaxASAAmountsBetanet        string                       `json:"max_asa_amounts_betanet,omitempty"`
}

// GetPolicySnapshotMessage requests the active read-only policy snapshot from
// the signer. The response is a signer-owned projection and must not be
// synthesized from local apadmin files.
type GetPolicySnapshotMessage struct {
	BaseMessage
	Target string `json:"target,omitempty"`
}

// PolicySnapshotMessage contains the active signer policy snapshot as canonical
// YAML suitable for read-only display.
type PolicySnapshotMessage struct {
	BaseMessage
	Success      bool   `json:"success"`
	Target       string `json:"target,omitempty"`
	IdentityID   string `json:"identity_id,omitempty"`
	PolicyYAML   string `json:"policy_yaml,omitempty"`
	PolicySHA256 string `json:"policy_sha256,omitempty"`
	Canonical    bool   `json:"canonical,omitempty"`
	Code         string `json:"code,omitempty"`
	Error        string `json:"error,omitempty"`
}

// ReplacePolicyMessage requests wholesale replacement of signer-owned policy
// YAML. ExpectedCurrentSHA256 is the optional canonical active policy SHA from
// a prior snapshot and lets clients fail closed when the signer policy changed
// since the file was previewed.
type ReplacePolicyMessage struct {
	BaseMessage
	Target                string `json:"target,omitempty"`
	PolicyYAML            string `json:"policy_yaml"`
	ExpectedCurrentSHA256 string `json:"expected_current_sha256,omitempty"`
}

// ReplacePolicyResultMessage returns the result of a wholesale policy
// replacement. On success, PolicyYAML is the resulting canonical active policy
// YAML, not necessarily the exact uploaded bytes.
type ReplacePolicyResultMessage struct {
	BaseMessage
	Success      bool   `json:"success"`
	Target       string `json:"target,omitempty"`
	IdentityID   string `json:"identity_id,omitempty"`
	PolicyYAML   string `json:"policy_yaml,omitempty"`
	PolicySHA256 string `json:"policy_sha256,omitempty"`
	Canonical    bool   `json:"canonical,omitempty"`
	Code         string `json:"code,omitempty"`
	Error        string `json:"error,omitempty"`
}

// ValidatePolicyMessage requests policy validation without mutating signer-owned files.
type ValidatePolicyMessage struct {
	BaseMessage
	Target     string `json:"target,omitempty"`
	PolicyYAML string `json:"policy_yaml"`
}

// ValidatePolicyResultMessage is the response to a validation-only policy request.
type ValidatePolicyResultMessage struct {
	BaseMessage
	Success    bool   `json:"success"`
	Target     string `json:"target,omitempty"`
	IdentityID string `json:"identity_id,omitempty"`
	Code       string `json:"code,omitempty"`
	Error      string `json:"error,omitempty"`
}

// UpdatePolicySettingMessage requests a change to a single policy setting.
type UpdatePolicySettingMessage struct {
	BaseMessage
	Key   string `json:"key"`
	Value string `json:"value"`
}

// UpdatePolicySettingResultMessage is the response to a policy setting change.
type UpdatePolicySettingResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Key     string `json:"key"`
	Value   string `json:"value,omitempty"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

// UpdatePolicyASAAmountsMessage requests an atomic change to network-scoped transfer guards.
type UpdatePolicyASAAmountsMessage struct {
	BaseMessage
	ReviewASAAmounts   map[string]string `json:"review_asa_amounts,omitempty"`
	MaxASAAmounts      map[string]string `json:"max_asa_amounts,omitempty"`
	ReviewAlgoPayments map[string]string `json:"review_algo_payments,omitempty"`
	MaxAlgoPayments    map[string]string `json:"max_algo_payments,omitempty"`
	Mainnet            string            `json:"mainnet,omitempty"`
	Testnet            string            `json:"testnet,omitempty"`
	Betanet            string            `json:"betanet,omitempty"`
}

// UpdatePolicyASAAmountsResultMessage is the response to a transfer guard change.
type UpdatePolicyASAAmountsResultMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ASAMetadataInfo struct {
	AssetID  uint64 `json:"asset_id"`
	Name     string `json:"name,omitempty"`
	UnitName string `json:"unit_name,omitempty"`
	Decimals uint64 `json:"decimals"`
	Source   string `json:"source,omitempty"`
}

type SearchASAMetadataMessage struct {
	BaseMessage
	Network string `json:"network"`
	Query   string `json:"query"`
}

type ASAMetadataResultsMessage struct {
	BaseMessage
	Network string            `json:"network"`
	Query   string            `json:"query"`
	Results []ASAMetadataInfo `json:"results,omitempty"`
	Code    string            `json:"code,omitempty"`
	Error   string            `json:"error,omitempty"`
}

type ResolveASAMetadataMessage struct {
	BaseMessage
	Network string `json:"network"`
	AssetID uint64 `json:"asset_id"`
}

type ASAMetadataResultMessage struct {
	BaseMessage
	Network string           `json:"network"`
	Asset   *ASAMetadataInfo `json:"asset,omitempty"`
	Code    string           `json:"code,omitempty"`
	Error   string           `json:"error,omitempty"`
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
