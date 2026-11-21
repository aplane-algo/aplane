// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type ProductServices interface {
	ProductRuntime() *productruntime.Runtime
	// VerifyPassphrase checks a login passphrase against the store root. A
	// passphrase that does not open the root must be reported as an error
	// wrapping crypto.ErrInvalidPassphrase: the login treats any other error
	// as a store root it cannot open and ends instead of asking again, so an
	// implementation that drops the sentinel ends the login on every typo.
	VerifyPassphrase(passphrase []byte) error
	UnlockIdentity(passphrase []byte) (bool, int, string, string)
	InitializeStore(req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult
	ChangeStorePassphrase(ctx context.Context, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult
	NewSessionIdentity(method string) *auth.Identity
	// EnrolledKeys lists the enrolled client keys.
	EnrolledKeys() []protocol.EnrolledKeyInfo
	// RevokeEnrolledKey removes one enrolled client key and closes its
	// connections, reporting how many were closed.
	RevokeEnrolledKey(ctx SessionContext, fingerprint string) (closedConnections int, err error)
	// RevokeAllEnrolledKeys removes every enrolled client key and closes
	// every client connection.
	RevokeAllEnrolledKeys(ctx SessionContext) (revoked, closedConnections int, err error)
	// PendingEnrollments lists the enrollment requests waiting for the
	// operator, oldest first.
	PendingEnrollments() []protocol.PendingEnrollmentInfo
	// ApproveEnrollment enrolls the key of a waiting request; label, when
	// set, replaces the requested label. It returns the label recorded.
	ApproveEnrollment(ctx SessionContext, fingerprint, label string) (string, error)
	// RejectEnrollment drops a waiting request without enrolling its key.
	RejectEnrollment(ctx SessionContext, fingerprint string) error
	// ImportClientKey enrolls an OpenSSH public-key line the operator
	// supplied.
	ImportClientKey(ctx SessionContext, publicKey, label string) (ImportedClientKey, error)
}

// ImportedClientKey is what an import recorded: the key's fingerprint, the
// label, whether the key was new to the registry, and whether the key line's
// comment, taken for the label when the operator gave none, was left out
// because it is not a label the registry admits.
type ImportedClientKey struct {
	Fingerprint    string
	Label          string
	Added          bool
	CommentRefused bool
}

type SettingsServices interface {
	BuildAdminSettings() adminproto.AdminSettings
	UpdateAdminSetting(req adminproto.UpdateAdminSettingRequest) error
	GetPolicy() adminproto.PolicyView
	GetPolicyDocumentAt(req adminproto.GetPolicyDocumentRequest) adminproto.PolicyDocumentResult
	GetPolicyContext() adminproto.PolicyContextView
	CheckPolicy(req adminproto.CheckPolicyRequest) adminproto.CheckPolicyResult
	ApplyPolicy(req adminproto.ApplyPolicyRequest) adminproto.ApplyPolicyResult
	ListASASet() adminproto.ListASASetResult
	LookupASA(req adminproto.LookupASARequest) adminproto.LookupASAResult
	AddASA(req adminproto.AddASARequest) adminproto.AddASAResult
	RemoveASA(req adminproto.RemoveASARequest) adminproto.RemoveASAResult
}

type KeyServices interface {
	ExportKey(ctx context.Context, req adminproto.ExportKeyRequest, deliver adminproto.ExportDelivery) adminproto.ExportKeyResult
	ListKeys() ([]adminproto.KeyInfo, error)
	GetKeyDetails(req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult
	PrepareGenerateKey(req adminproto.PrepareGenerateKeyRequest) adminproto.PrepareGenerateKeyResult
	GenerateKey(ctx context.Context, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult
	DeleteKey(ctx context.Context, req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult
	ImportKey(ctx context.Context, req adminproto.ImportKeyRequest) adminproto.ImportKeyResult
}

type BackupServices interface {
	BackupIdentity(req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult
	ListBackups() adminproto.ListBackupsResult
	DeleteBackup(req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult
	BeginBackupImport(req adminproto.BeginBackupImportRequest) adminproto.BeginBackupImportResult
	AppendBackupImport(req adminproto.AppendBackupImportRequest) adminproto.AppendBackupImportResult
	CommitBackupImport(req adminproto.CommitBackupImportRequest) adminproto.CommitBackupImportResult
	AbortBackupImport(req adminproto.AbortBackupImportRequest) adminproto.AbortBackupImportResult
	ReadBackupChunk(req adminproto.ReadBackupChunkRequest) adminproto.ReadBackupChunkResult
	PreviewRestore(req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult
	RestoreBackup(req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult
	RollbackRestore(req adminproto.RollbackRestoreRequest) adminproto.RollbackRestoreResult
	ReconcileStore() adminproto.ReconcileStoreResult
}

type TemplateServices interface {
	ListLibraryTemplates() adminproto.ListLibraryTemplatesResult
	InstallLibraryTemplate(req adminproto.InstallLibraryTemplateRequest) adminproto.InstallLibraryTemplateResult
	ListInstalledTemplates() adminproto.ListInstalledTemplatesResult
	ShowInstalledTemplate(req adminproto.ShowInstalledTemplateRequest) adminproto.ShowInstalledTemplateResult
	ShowLibraryTemplate(req adminproto.ShowLibraryTemplateRequest) adminproto.ShowLibraryTemplateResult
	ImportInstalledTemplate(req adminproto.ImportInstalledTemplateRequest) adminproto.ImportInstalledTemplateResult
	RemoveInstalledTemplate(req adminproto.RemoveInstalledTemplateRequest) adminproto.RemoveInstalledTemplateResult
	ActivateKeyType(req adminproto.ActivateKeyTypeRequest) adminproto.ActivateKeyTypeResult
	DeactivateKeyType(req adminproto.DeactivateKeyTypeRequest) adminproto.DeactivateKeyTypeResult
	ListKeyTypes() adminproto.ListKeyTypesResult
}

type StoreInspectionServices interface {
	ListCosignerReferences() adminproto.ListCosignerReferencesResult
	GetCosignerReference(req adminproto.GetCosignerReferenceRequest) adminproto.GetCosignerReferenceResult
	ImportCosignerReference(req adminproto.ImportCosignerReferenceRequest) adminproto.ImportCosignerReferenceResult
	RemoveCosignerReference(req adminproto.RemoveCosignerReferenceRequest) adminproto.RemoveCosignerReferenceResult
	ExportCosignerPublic(req adminproto.ExportCosignerPublicRequest) adminproto.ExportCosignerPublicResult
	ListGenerations() adminproto.GenerationInventory
	PruneGenerationQuarantine(req adminproto.PruneGenerationQuarantineRequest) adminproto.PruneGenerationQuarantineResult
	DiscardAbandonedGenerations(req adminproto.DiscardAbandonedGenerationsRequest) adminproto.DiscardAbandonedGenerationsResult
	ListDeletedArchive() adminproto.DeletedArchiveInventory
	PruneDeletedArchive(req adminproto.PruneDeletedArchiveRequest) adminproto.PruneDeletedArchiveResult
}

type AuthorizationAudit interface {
	LogAuthorizationDenied(ctx SessionContext, action auth.Action, resource auth.Resource, reason string)
}

type SessionDeps struct {
	Product     ProductServices
	Settings    SettingsServices
	Keys        KeyServices
	Backups     BackupServices
	Templates   TemplateServices
	Inspection  StoreInspectionServices
	Authorizer  auth.Authorizer
	Audit       AuthorizationAudit
	NodeFailure func() error
}
