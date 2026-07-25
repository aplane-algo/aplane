// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

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
	UserAutoApprove      bool
	LockOnDisconnect     bool
	PassphraseTimeout    string
	PassphraseMethod     string
	NodeRole             string
	SSHEnabled           bool
	SSHListenAddress     string
	SSHPort              int
	SSHFingerprint       string
	SSHClients           int
	SignerPort           int
	TEALCompileNet       string
	EndpointAdvertiseURL string
	EndpointDisplayURL   string
	Theme                string
}

const (
	AdminSettingUserAutoApprove      = "user_auto_approve"
	AdminSettingLockOnDisconnect     = "lock_on_disconnect"
	AdminSettingPassphraseTimeout    = "passphrase_timeout"
	AdminSettingTheme                = "theme"
	AdminSettingSSHListenAddress     = "ssh.listen_address"
	AdminSettingEndpointAdvertiseURL = "endpoint.advertise_url"
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
	// SkippedKeys maps address -> reason for keys excluded from an all-keys
	// backup because their payload failed canonical validation.
	SkippedKeys map[string]string
	Code        string
	Error       string
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
	Success                  bool
	KeysMigrated             int
	TemplatesMigrated        int
	RecoveredFilesMigrated   int
	PolicySidecarsMigrated   int
	NodeRoleSidecarsMigrated int
	Code                     string
	Error                    string
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

// RecoverBackupRequest selects archive entries for inactive recovery.
type RecoverBackupRequest struct {
	ArchivePath      string
	Addresses        []string
	ExportPassphrase []byte
}

// RecoverBackupResult identifies one atomically published inactive batch.
type RecoverBackupResult struct {
	Success         bool
	RestoreID       string
	ArchiveName     string
	ArchiveChecksum string
	EntryCount      int
	Code            string
	Error           string
}

// RecoveredBatchInfo is the non-secret inventory projection of one batch.
type RecoveredBatchInfo struct {
	RestoreID          string
	CreatedAt          int64
	ArchiveName        string
	ArchiveChecksum    string
	SourceNodeRole     string
	SourcePolicyStatus string
	SourcePolicySHA256 string
	EntryCount         int
}

// ListRecoveredResult contains inactive recovered batches.
type ListRecoveredResult struct {
	Batches []RecoveredBatchInfo
	Code    string
	Error   string
}

// DestinationApprovalMode describes the destination's effective unmatched
// signing behavior.
type DestinationApprovalMode string

const (
	// DestinationApprovalManualDefault requires unmatched requests to use
	// operator approval.
	DestinationApprovalManualDefault DestinationApprovalMode = "manual_default"
	// DestinationApprovalAutoApproveFallback permits unmatched requests to
	// skip operator approval.
	DestinationApprovalAutoApproveFallback DestinationApprovalMode = "auto_approve_fallback"
	// DestinationApprovalNotApplicable is used for identities without an
	// operator-default approval mode.
	DestinationApprovalNotApplicable DestinationApprovalMode = "not_applicable"
)

// RecoveredReviewEntry identifies one validated inactive entry.
type RecoveredReviewEntry struct {
	Selector string
	Category string
	KeyType  string
}

// RecoveredActiveConflict fingerprints an active credential that activation
// would replace.
type RecoveredActiveConflict struct {
	Selector string
	Category string
	KeyType  string
	SHA256   string
}

// RecoveryPolicyChange is one ordered factual policy difference.
type RecoveryPolicyChange struct {
	Category    string
	Selector    string
	Path        string
	Source      string
	Destination string
}

// ReviewRecoveredResult pins one review of current destination state.
type ReviewRecoveredResult struct {
	Success                      bool
	RestoreID                    string
	State                        string
	ArchiveChecksum              string
	SourceNodeRole               string
	SourcePolicyStatus           string
	SourcePolicySHA256           string
	DestinationPolicySHA256      string
	DestinationApprovalMode      DestinationApprovalMode
	UnattendedSigningWarning     string
	PolicyComparison             string
	SecurityChanges              []RecoveryPolicyChange
	ChangedPaths                 []string
	UnknownSourceSettings        []string
	Entries                      []RecoveredReviewEntry
	ActiveConflicts              []RecoveredActiveConflict
	ReviewToken                  string
	AcknowledgePolicyTransition  bool
	AcknowledgeUnattendedSigning bool
	ReplaceExisting              bool
	Code                         string
	Error                        string
}

// ActivateRecoveredRequest binds activation to one reviewed destination
// state and records each security-sensitive operator acknowledgement.
type ActivateRecoveredRequest struct {
	RestoreID                    string
	ReviewToken                  string
	AcknowledgePolicyTransition  bool
	AcknowledgeUnattendedSigning bool
	ReplaceExisting              bool
}

// ActivateRecoveredResult describes credentials made active by one atomic
// activation attempt.
type ActivateRecoveredResult struct {
	Success                 bool
	RestoreID               string
	Activated               []RecoveredReviewEntry
	Warnings                []string
	KeyCount                int
	ArchiveSHA256           string
	SourcePolicySHA256      string
	DestinationPolicySHA256 string
	PolicyComparison        string
	ReplaceExisting         bool
	Resumed                 bool
	Code                    string
	Error                   string
}

// RollbackRecoveredRequest identifies one incomplete activation to reverse.
type RollbackRecoveredRequest struct {
	RestoreID string
}

// RollbackRecoveredResult reports restoration of the pre-activation state.
type RollbackRecoveredResult struct {
	Success   bool
	RestoreID string
	KeyCount  int
	Code      string
	Error     string
}

// PurgeRecoveredRequest identifies one inactive batch to delete.
type PurgeRecoveredRequest struct {
	RestoreID string
}

// PurgeRecoveredResult reports deletion of one inactive batch.
type PurgeRecoveredResult struct {
	Success   bool
	RestoreID string
	Code      string
	Error     string
}

// UpdateAdminSettingRequest is the admin-domain request to change one setting.
type UpdateAdminSettingRequest struct {
	Key   string
	Value string
}

// PolicyTarget identifies which policy document an admin policy operation uses.
type PolicyTarget string

const (
	PolicyTargetSigner PolicyTarget = "signer"
	PolicyTargetSentry PolicyTarget = "sentry"
)

// NormalizePolicyTarget maps the legacy omitted target to signer and trims the
// raw protocol value. Target validity is enforced by the signer service.
func NormalizePolicyTarget(raw string) PolicyTarget {
	target := strings.ToLower(strings.TrimSpace(raw))
	if target == "" {
		return PolicyTargetSigner
	}
	return PolicyTarget(target)
}

// PolicySnapshot is the admin-domain read-only view of the active signer
// policy. PolicyYAML is canonical YAML generated from the active stored policy
// snapshot, not bytes read by the admin client.
type PolicySnapshot struct {
	Success      bool
	Target       PolicyTarget
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
	Target                PolicyTarget
	PolicyYAML            string
	ExpectedCurrentSHA256 string
}

// ValidatePolicyRequest is the admin-domain request to validate policy YAML
// without replacing signer-owned files.
type ValidatePolicyRequest struct {
	Target     PolicyTarget
	PolicyYAML string
}

// ValidatePolicyResult is the admin-domain response to a validation-only policy
// request.
type ValidatePolicyResult struct {
	Success    bool
	Target     PolicyTarget
	IdentityID string
	Code       string
	Error      string
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
