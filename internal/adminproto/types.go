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
	Code            string
	Error           string
}

type BackupInfo struct {
	Path      string
	FileName  string
	CreatedAt int64
	Size      int64
	Checksum  string
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

const (
	BackupTransferChunkBytes = 256 * 1024
	// MaxBackupImportBytes bounds daemon-owned incomplete backup uploads.
	// Signer backups contain credential records rather than arbitrary user data;
	// one GiB leaves ample operational headroom while bounding disk exhaustion.
	MaxBackupImportBytes int64 = 1 << 30
)

type BeginBackupImportRequest struct {
	FileName string
}

type BeginBackupImportResult struct {
	Success  bool
	UploadID string
	Code     string
	Error    string
}

type AppendBackupImportRequest struct {
	UploadID string
	Offset   int64
	Data     []byte
}

type AppendBackupImportResult struct {
	Success    bool
	NextOffset int64
	Code       string
	Error      string
}

type CommitBackupImportRequest struct {
	UploadID         string
	FileName         string
	ExpectedSize     int64
	ExpectedSHA256   string
	ExportPassphrase []byte
}

type CommitBackupImportResult struct {
	Success bool
	Backup  BackupInfo
	Warning string
	Code    string
	Error   string
}

type AbortBackupImportRequest struct {
	UploadID string
}

type AbortBackupImportResult struct {
	Success bool
	Code    string
	Error   string
}

type ReadBackupChunkRequest struct {
	FileName string
	Offset   int64
}

type ReadBackupChunkResult struct {
	Success  bool
	FileName string
	Offset   int64
	Data     []byte
	EOF      bool
	Code     string
	Error    string
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
	PolicySidecarsMigrated   int
	NodeRoleSidecarsMigrated int
	PriorGenerations         int
	HelperWarning            string
	RootCommitted            bool
	RotationPending          bool
	Code                     string
	Error                    string
}

type RestoreKeyInfo struct {
	Address       string
	KeyType       string
	AlreadyExists bool
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

// RestoreCredential identifies one complete managed credential selected from
// an authenticated credential backup.
type RestoreCredential struct {
	Selector string
	Category string
	KeyType  string
}

// RestoreConflict reports a destination credential that differs from the
// incoming canonical plaintext or cannot be decoded for comparison.
type RestoreConflict struct {
	Selector       string
	Category       string
	KeyType        string
	ExistingSHA256 string
	Reason         string
}

// RestoreBackupRequest performs one direct, generational credential restore.
// OperationID is supplied by the protocol boundary for durable audit and
// generation-manifest correlation.
type RestoreBackupRequest struct {
	OperationID      string
	ArchivePath      string
	Addresses        []string
	ExportPassphrase []byte
	ReplaceExisting  bool
}

// RestoreBackupResult describes one direct credential restore transaction.
type RestoreBackupResult struct {
	Success       bool
	OperationID   string
	ArchiveSHA256 string
	GenerationID  string
	// CommitUncertain is process-local audit metadata. It is set when the
	// CURRENT flip is visible but its durability could not be confirmed and
	// is deliberately not projected onto the admin protocol.
	CommitUncertain bool
	Restored        []RestoreCredential
	Identical       []RestoreCredential
	Conflicts       []RestoreConflict
	KeyCount        int
	Code            string
	Error           string
}

// RollbackRestoreRequest identifies an authenticated request to reconstruct
// the sealed parent of the latest clean credential restore.
type RollbackRestoreRequest struct {
	OperationID string
}

type RollbackRestoreResult struct {
	Success      bool
	OperationID  string
	GenerationID string
	KeyCount     int
	Code         string
	Error        string
}

type ReconcileStoreResult struct {
	Success      bool
	GenerationID string
	KeyCount     int
	State        string
	Code         string
	Error        string
}

// SentryReferenceInfo is the admin-domain projection of a stored public
// sentry reference. It never contains private witness material.
type SentryReferenceInfo struct {
	Schema            string
	Name              string
	ComponentKey      string
	KeyType           string
	PublicKeyEncoding string
	PublicKeyHex      string
	PublicKeySize     int
	PublicKeySHA256   string
	ImportedAt        string
	MigrationOrigin   string
}

type ListSentryReferencesResult struct {
	References []SentryReferenceInfo
	Code       string
	Error      string
}

type GetSentryReferenceRequest struct {
	Name string
}

type GetSentryReferenceResult struct {
	Success   bool
	Reference SentryReferenceInfo
	Code      string
	Error     string
}

type ImportSentryReferenceRequest struct {
	Name         string
	EnvelopeJSON string
}

type ImportSentryReferenceResult struct {
	Success   bool
	Reference SentryReferenceInfo
	Code      string
	Error     string
}

type RemoveSentryReferenceRequest struct {
	Name string
}

type RemoveSentryReferenceResult struct {
	Success      bool
	Name         string
	ComponentKey string
	Removed      bool
	Code         string
	Error        string
}

type ExportSentryPublicRequest struct {
	WitnessKeyID string
}

type ExportSentryPublicResult struct {
	Success      bool
	WitnessKeyID string
	EnvelopeJSON string
	Code         string
	Error        string
}

type GenerationInventory struct {
	Current                string
	SealedPriors           []string
	PendingAttempts        []string
	PendingStaging         []string
	RetainedUnsealedParent string
	Code                   string
	Error                  string
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
	Success bool
	Target  PolicyTarget
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
