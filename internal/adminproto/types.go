// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import "github.com/aplane-algo/aplane/internal/signerapi"

// KeyInfo is the admin-domain view of a key listed over the admin protocol.
type KeyInfo struct {
	Address                  string
	KeyType                  string
	Name                     string
	TemplateProvenanceStatus string
	TemplateProvenanceNote   string
}

// AdminSettings is the admin-domain view of current admin settings.
type AdminSettings struct {
	UserAutoApprove   bool
	LockOnDisconnect  bool
	PassphraseTimeout string
	PassphraseMethod  string
	SSHEnabled        bool
	SSHPort           int
	SSHFingerprint    string
	SSHClients        int
	SignerPort        int
	TEALCompileNet    string
	Theme             string
}

const (
	AdminSettingUserAutoApprove   = "user_auto_approve"
	AdminSettingLockOnDisconnect  = "lock_on_disconnect"
	AdminSettingPassphraseTimeout = "passphrase_timeout"
	AdminSettingTheme             = "theme"
)

// SignerLockedNotification is the admin-domain notification emitted when the signer locks.
type SignerLockedNotification struct {
	Reason string
}

// KeysChangedNotification is the admin-domain notification emitted when key inventory changes.
type KeysChangedNotification struct {
	KeyCount int
}

// BackupIdentityRequest is the admin-domain request to create a signer-managed
// backup archive for the currently bound identity.
type BackupIdentityRequest struct {
	ExportPassphrase []byte
	Addresses        []string
}

// BackupIdentityResult is the admin-domain result of backup creation.
type BackupIdentityResult struct {
	Success         bool
	ArchivePath     string
	ArchiveChecksum string
	ArchiveSize     int64
	KeyCount        int
	Addresses       []string
	Verified        bool
	Code            string
	Error           string
}

type BackupInfo struct {
	Path      string
	FileName  string
	CreatedAt int64
	Size      int64
	Checksum  string
	Verified  bool
}

type ListBackupsResult struct {
	Backups []BackupInfo
	Code    string
	Error   string
}

type DeleteBackupRequest struct {
	ArchivePath string
}

type DeleteBackupResult struct {
	Success bool
	Code    string
	Error   string
}

type InitializeStoreRequest struct {
	Passphrase []byte
}

type InitializeStoreResult struct {
	Success       bool
	MetadataDir   string
	HelperWarning string
	Code          string
	Error         string
}

type ChangeStorePassphraseRequest struct {
	CurrentPassphrase []byte
	NewPassphrase     []byte
}

type ChangeStorePassphraseResult struct {
	Success                bool
	KeysMigrated           int
	TemplatesMigrated      int
	PolicySidecarsMigrated int
	Code                   string
	Error                  string
}

type RestoreKeyInfo struct {
	Address       string
	KeyType       string
	AlreadyExists bool
	HasTemplate   bool
	TemplateType  string
	Error         string
}

type RestoreError struct {
	Address string
	Error   string
}

type RestoreWarning struct {
	Address string
	KeyType string
	Warning string
}

type PreviewRestoreRequest struct {
	ArchivePath      string
	ExportPassphrase []byte
}

type RestorePreviewResult struct {
	ArchivePath string
	Keys        []RestoreKeyInfo
	Errors      []RestoreError
	Code        string
	Error       string
}

type RestoreBackupRequest struct {
	ArchivePath      string
	Addresses        []string
	Overwrite        bool
	ExportPassphrase []byte
}

type RestoreBackupResult struct {
	ArchivePath string
	Success     bool
	Restored    []RestoreKeyInfo
	Skipped     []RestoreKeyInfo
	Errors      []RestoreError
	Warnings    []RestoreWarning
	KeyCount    int
	Code        string
	Error       string
}

// UpdateAdminSettingRequest is the admin-domain request to change one setting.
type UpdateAdminSettingRequest struct {
	Key   string
	Value string
}

// PolicySettings is the admin-domain view of current policy settings.
type PolicySettings struct {
	RejectForeignRekey          bool
	RejectCloseRemainder        bool
	RejectAssetClose            bool
	RejectClawback              bool
	AlwaysReviewWarnings        bool
	AutoApproveSelfNoOpTransfer bool
	MaxFeeMicroAlgos            string
	ReviewAlgoPayments          map[string]string
	MaxAlgoPayments             map[string]string
	PolicyNetworks              []string
	ReviewASAAmounts            map[string]string
	MaxASAAmounts               map[string]string
	PolicyASAMetadata           map[string][]ASAMetadataInfo
	MaxASAAmountsMainnet        string
	MaxASAAmountsTestnet        string
	MaxASAAmountsBetanet        string
}

// PolicySnapshot is the admin-domain read-only view of the active signer
// policy. PolicyYAML is canonical YAML generated from the active stored policy
// snapshot, not bytes read by the admin client.
type PolicySnapshot struct {
	Success      bool
	IdentityID   string
	PolicyYAML   string
	PolicySHA256 string
	Canonical    bool
	Code         string
	Error        string
}

// ReplacePolicyRequest is the admin-domain request to replace policy.yaml as a
// whole file. ExpectedCurrentSHA256 is optional optimistic concurrency against
// the canonical active snapshot.
type ReplacePolicyRequest struct {
	PolicyYAML            string
	ExpectedCurrentSHA256 string
}

const (
	PolicySettingRejectForeignRekey          = "reject_foreign_rekey"
	PolicySettingRejectCloseRemainder        = "reject_close_remainder"
	PolicySettingRejectAssetClose            = "reject_asset_close"
	PolicySettingRejectClawback              = "reject_clawback"
	PolicySettingAlwaysReviewWarnings        = "always_review_warnings"
	PolicySettingAutoApproveSelfNoOpTransfer = "auto_approve_self_noop_transfer"
	PolicySettingMaxFeeMicroAlgos            = "max_fee_microalgos"
	PolicySettingMaxASAAmountsMainnet        = "max_asa_amounts_mainnet"
	PolicySettingMaxASAAmountsTestnet        = "max_asa_amounts_testnet"
	PolicySettingMaxASAAmountsBetanet        = "max_asa_amounts_betanet"
)

// UpdatePolicySettingRequest is the admin-domain request to change one policy setting.
type UpdatePolicySettingRequest struct {
	Key   string
	Value string
}

// UpdatePolicyASAAmountsRequest is the admin-domain request to replace network-scoped transfer guards.
type UpdatePolicyASAAmountsRequest struct {
	ReviewASAAmounts   map[string]string
	MaxASAAmounts      map[string]string
	ReviewAlgoPayments map[string]string
	MaxAlgoPayments    map[string]string
	Mainnet            string
	Testnet            string
	Betanet            string
}

type ASAMetadataInfo struct {
	AssetID  uint64
	Name     string
	UnitName string
	Decimals uint64
	Source   string
}

type SearchASAMetadataRequest struct {
	Network string
	Query   string
}

type ASAMetadataResults struct {
	Network string
	Query   string
	Results []ASAMetadataInfo
	Code    string
	Error   string
}

type ResolveASAMetadataRequest struct {
	Network string
	AssetID uint64
}

type ASAMetadataResult struct {
	Network string
	Asset   ASAMetadataInfo
	Code    string
	Error   string
}

// GenerateKeyRequest is the admin-domain request to generate a key.
type GenerateKeyRequest struct {
	KeyType    string
	Name       string
	Parameters map[string]string
}

// GenerateKeyResult is the admin-domain result of key generation.
//
// Recovery material (mnemonic / word count) is intentionally absent: it is
// produced inside the signer keyadmin layer and persisted to the encrypted
// keyfile, but never crosses the admin-protocol boundary.
type GenerateKeyResult struct {
	Success    bool
	Address    string
	KeyType    string
	Parameters map[string]string
	Code       string
	Error      string
}

// DeleteKeyRequest is the admin-domain request to delete a key.
type DeleteKeyRequest struct {
	Address string
}

// DeleteKeyResult is the admin-domain result of key deletion.
type DeleteKeyResult struct {
	Success bool
	Code    string
	Error   string
}

// ImportKeyRequest is the admin-domain request to import a key.
type ImportKeyRequest struct {
	KeyType    string
	Mnemonic   string
	Parameters map[string]string
}

// ImportKeyResult is the admin-domain result of key import.
type ImportKeyResult struct {
	Success bool
	Address string
	KeyType string
	Code    string
	Error   string
}

// GetKeyDetailsRequest is the admin-domain request for detailed key info.
type GetKeyDetailsRequest struct {
	Address string
}

// GetKeyDetailsResult is the admin-domain response for detailed key info.
type GetKeyDetailsResult struct {
	Success                  bool
	Address                  string
	KeyType                  string
	PublicKeyHex             string
	Parameters               map[string]string
	DisplayTEAL              string
	TemplateProvenanceStatus string
	TemplateProvenanceNote   string
	Code                     string
	Error                    string
}

type LibraryTemplateInfo struct {
	KeyType      string
	TemplateType string
	DisplayName  string
	Description  string
	SourcePath   string
	FileName     string
	Parameters   []signerapi.CreationParamInfo
	RuntimeArgs  []signerapi.RuntimeArgInfo
	Installed    bool
	Enabled      bool
	Conflict     string
	Invalid      string
}

type ListLibraryTemplatesResult struct {
	Templates []LibraryTemplateInfo
	Code      string
	Error     string
}

type InstallLibraryTemplateRequest struct {
	KeyType      string
	TemplateType string
}

type InstallLibraryTemplateResult struct {
	Success       bool
	KeyType       string
	TemplateType  string
	AlreadyExists bool
	Code          string
	Error         string
}

type InstalledTemplateInfo struct {
	KeyType      string
	TemplateType string
	Size         int64
	Enabled      bool
}

type ListInstalledTemplatesResult struct {
	Templates []InstalledTemplateInfo
	Code      string
	Error     string
}

type ShowInstalledTemplateRequest struct {
	KeyType string
}

type ShowInstalledTemplateResult struct {
	Success      bool
	KeyType      string
	TemplateType string
	TemplateYAML []byte
	Code         string
	Error        string
}

type ShowLibraryTemplateRequest struct {
	KeyType      string
	TemplateType string
}

type ShowLibraryTemplateResult struct {
	Success       bool
	KeyType       string
	TemplateType  string
	SourcePath    string
	SourceSHA256  string
	SourceModTime int64
	TemplateYAML  []byte
	Code          string
	Error         string
}

type ImportInstalledTemplateRequest struct {
	TemplateYAML []byte
}

type ImportInstalledTemplateResult struct {
	Success       bool
	KeyType       string
	TemplateType  string
	AlreadyExists bool
	Code          string
	Error         string
}

type RemoveInstalledTemplateRequest struct {
	KeyType string
}

type RemoveInstalledTemplateResult struct {
	Success      bool
	KeyType      string
	TemplateType string
	Removed      bool
	Code         string
	Error        string
}

type ActivateKeyTypeRequest struct {
	KeyType string
}

type ActivateKeyTypeResult struct {
	Success       bool
	KeyType       string
	AlreadyExists bool
	Code          string
	Error         string
}

type DeactivateKeyTypeRequest struct {
	KeyType string
}

type DeactivateKeyTypeResult struct {
	Success bool
	KeyType string
	Removed bool
	Code    string
	Error   string
}

type ListKeyTypesResult struct {
	KeyTypes []signerapi.KeyTypeInfo
	Code     string
	Error    string
}
