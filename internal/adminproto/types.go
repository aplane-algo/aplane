// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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
	Code                     string
	Error                    string
}

type RestoreKeyInfo struct {
	Address       string
	KeyType       string
	AlreadyExists bool
	HasPolicy     bool
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
	// store-root replacement is visible but its durability could not be confirmed and
	// is deliberately not projected onto the admin protocol.
	CommitUncertain bool
	Restored        []RestoreCredential
	Identical       []RestoreCredential
	Conflicts       []RestoreConflict
	// PoliciesRestored lists the cosigner keys whose archived policy was
	// installed.
	PoliciesRestored []string
	KeyCount         int
	Code             string
	Error            string
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

// CosignerReferenceInfo is the admin-domain projection of a stored public
// cosigner reference. It never contains private witness material.
type CosignerReferenceInfo struct {
	Schema            string
	Name              string
	ComponentKey      string
	KeyType           string
	PublicKeyEncoding string
	PublicKeyHex      string
	PublicKeySize     int
	PublicKeySHA256   string
	ImportedAt        string
}

type ListCosignerReferencesResult struct {
	References []CosignerReferenceInfo
	Code       string
	Error      string
}

type GetCosignerReferenceRequest struct {
	Name string
}

type GetCosignerReferenceResult struct {
	Success   bool
	Reference CosignerReferenceInfo
	Code      string
	Error     string
}

type ImportCosignerReferenceRequest struct {
	Name         string
	EnvelopeJSON string
}

type ImportCosignerReferenceResult struct {
	Success   bool
	Reference CosignerReferenceInfo
	Code      string
	Error     string
}

type RemoveCosignerReferenceRequest struct {
	Name string
}

type RemoveCosignerReferenceResult struct {
	Success      bool
	Name         string
	ComponentKey string
	Removed      bool
	Code         string
	Error        string
}

type ExportCosignerPublicRequest struct {
	WitnessKeyID string
}

type ExportCosignerPublicResult struct {
	Success      bool
	WitnessKeyID string
	EnvelopeJSON string
	Code         string
	Error        string
}

type GenerationInventory struct {
	Current                string
	SealedPriors           []string
	Quarantined            []QuarantinedGenerationInfo
	PendingStaging         []string
	RetainedUnsealedParent string
	Code                   string
	Error                  string
}

type QuarantinedGenerationInfo struct {
	GenerationID         string
	ParentID             string
	ManifestSHA256       string
	LiveInventorySHA256  string
	AtMintInventoryMatch bool
	EntryCount           int
	EncodedBytes         int64
	TermVerified         int
	TermUnavailable      int
	TermFailed           int
}

type PruneGenerationQuarantineRequest struct {
	GenerationIDs []string
}

type PrunedQuarantinedGeneration struct {
	GenerationID  string
	EncodedBytes  int64
	AlreadyAbsent bool
}

type PruneGenerationQuarantineResult struct {
	Success bool
	Pruned  []PrunedQuarantinedGeneration
	Code    string
	Error   string
}

type DiscardAbandonedGenerationsRequest struct {
	GenerationIDs []string
}

type DiscardAbandonedGenerationsResult struct {
	Success   bool
	Discarded []PrunedQuarantinedGeneration
	Code      string
	Error     string
}

type DeletedArchiveInventory struct {
	Entries      []DeletedArchiveEntry
	EntryCount   int
	EncodedBytes int64
	Warning      bool
	Code         string
	Error        string
}

type DeletedArchiveEntry struct {
	Path         string
	EncodedBytes int64
}

type PruneDeletedArchiveRequest struct {
	Entries []string
}

type PrunedDeletedArchiveEntry struct {
	Path          string
	EncodedBytes  int64
	AlreadyAbsent bool
}

type PruneDeletedArchiveResult struct {
	Success bool
	Pruned  []PrunedDeletedArchiveEntry
	Code    string
	Error   string
}

// UpdateAdminSettingRequest is the admin-domain request to change one setting.
type UpdateAdminSettingRequest struct {
	Key   string
	Value string
}

// PolicyDocument is one policy document's exact bytes in a check or apply
// request. Key is the Witness Key ID of a cosigner document and empty for the
// signer document.
type PolicyDocument struct {
	Key      string
	Document string
}

// PolicyDocumentInfo describes one stored policy document without its bytes.
type PolicyDocumentInfo struct {
	Key          string
	SHA256       string
	Size         int
	SignedAtUnix int64
}

// PolicyDocumentResult is one stored policy document's exact bytes.
type PolicyDocumentResult struct {
	Success      bool
	Key          string
	Document     string
	SHA256       string
	SignedAtUnix int64
	Code         string
	Error        string
}

// Cosigner key policy coverage states.
const (
	PolicyKeyActive   = "active"
	PolicyKeyNoPolicy = "no_policy"
	PolicyKeyNotHeld  = "key_not_held"
)

// PolicyKeyStatus reports one cosigner key's policy coverage.
type PolicyKeyStatus struct {
	Key    string
	Status string
}

// PolicyProblem is one validation problem located by cosigner key and JSON
// Pointer.
type PolicyProblem struct {
	Key     string
	Pointer string
	Message string
}

// PolicyView summarizes the node's active policy: each document without its
// bytes, cosigner key coverage, and the set digest that apply uses as its
// concurrency base.
type PolicyView struct {
	Success         bool
	NodeRole        string
	Documents       []PolicyDocumentInfo
	Keys            []PolicyKeyStatus
	PolicySetSHA256 string
	GenerationID    string
	Code            string
	Error           string
}

// Wire projects the view onto the admin protocol's policy message.
func (v PolicyView) Wire(id string) protocol.PolicyMessage {
	msg := protocol.PolicyMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypePolicy, ID: id},
		Success:         v.Success,
		NodeRole:        v.NodeRole,
		PolicySetSHA256: v.PolicySetSHA256,
		GenerationID:    v.GenerationID,
		Code:            v.Code,
		Error:           v.Error,
	}
	for _, doc := range v.Documents {
		msg.Documents = append(msg.Documents, protocol.PolicyDocumentInfoWire{
			Key: doc.Key, SHA256: doc.SHA256, Size: doc.Size, SignedAtUnix: doc.SignedAtUnix,
		})
	}
	for _, key := range v.Keys {
		msg.Keys = append(msg.Keys, protocol.PolicyKeyStatusWire{Key: key.Key, Status: key.Status})
	}
	return msg
}

// CheckPolicyRequest validates candidate documents without writing. Remove
// lists cosigner keys the candidate change would delete.
type CheckPolicyRequest struct {
	Documents []PolicyDocument
	Remove    []string
}

// CheckPolicyResult reports validation problems; Valid means no errors.
type CheckPolicyResult struct {
	Success  bool
	Valid    bool
	Errors   []PolicyProblem
	Warnings []PolicyProblem
	Code     string
	Error    string
}

// ApplyPolicyRequest replaces policy documents in one generation commit.
type ApplyPolicyRequest struct {
	Documents               []PolicyDocument
	Remove                  []string
	ExpectedPolicySetSHA256 string
}

// ApplyPolicyResult reports an apply; Policy is the new active policy.
type ApplyPolicyResult struct {
	Success         bool
	Errors          []PolicyProblem
	Policy          *PolicyView
	CommitUncertain bool
	Code            string
	Error           string
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
