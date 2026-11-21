// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	algocrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type queueConn struct {
	reads  [][]byte
	writes [][]byte
}

func (c *queueConn) ReadMessage() ([]byte, error) {
	if len(c.reads) == 0 {
		return nil, errors.New("eof")
	}
	msg := c.reads[0]
	c.reads = c.reads[1:]
	return msg, nil
}

func (c *queueConn) WriteMessage(data []byte) error {
	buf := make([]byte, len(data))
	copy(buf, data)
	c.writes = append(c.writes, buf)
	return nil
}

func (c *queueConn) RemoteAddr() string { return "test" }
func (c *queueConn) Close() error       { return nil }

type stubServices struct {
	exportResult adminproto.ExportKeyResult
	exportCalls  int
	runtime      *productruntime.Runtime
	verifyErrs   []error
	unlockOK     bool
	unlockErrMsg string
	unlockCode   string
	newIdentity  *auth.Identity
	verifyCalls  int
	unlockCalls  int

	listLibraryCalls       int
	installLibraryCalls    int
	listInstalledCalls     int
	showInstalledCalls     int
	showLibraryCalls       int
	importInstalledCalls   int
	removeInstalledCalls   int
	activateKeyTypeCalls   int
	deactivateKeyTypeCalls int
	listKeyTypesCalls      int
	prepareGenerateCalls   int
	lastPrepareGenerate    adminproto.PrepareGenerateKeyRequest
	prepareGenerateResult  adminproto.PrepareGenerateKeyResult
	generateKeyCalls       int
	importKeyCalls         int
	backupCalls            int
	listBackupsCalls       int
	deleteBackupCalls      int

	beginBackupImportCalls   int
	appendBackupImportCalls  int
	commitBackupImportCalls  int
	readBackupChunkCalls     int
	lastCommitBackupImport   adminproto.CommitBackupImportRequest
	commitBackupImportResult adminproto.CommitBackupImportResult
	readBackupChunkResult    adminproto.ReadBackupChunkResult

	changePassphraseCalls  int
	initializeStoreCalls   int
	previewRestoreCalls    int
	restoreBackupCalls     int
	rollbackRestoreCalls   int
	reconcileStoreCalls    int
	getPolicyCalls         int
	checkPolicyCalls       int
	applyPolicyCalls       int
	addASACalls            int
	removeASACalls         int
	addASAResult           adminproto.AddASAResult
	removeASAResult        adminproto.RemoveASAResult
	lastInstallTemplate    adminproto.InstallLibraryTemplateRequest
	lastShowInstalled      adminproto.ShowInstalledTemplateRequest
	lastShowLibrary        adminproto.ShowLibraryTemplateRequest
	lastImportInstalled    adminproto.ImportInstalledTemplateRequest
	lastRemoveInstalled    adminproto.RemoveInstalledTemplateRequest
	lastActivateKeyType    adminproto.ActivateKeyTypeRequest
	lastDeactivateKeyType  adminproto.DeactivateKeyTypeRequest
	lastGenerateKeyContext context.Context
	lastGenerateKey        adminproto.GenerateKeyRequest
	lastImportKey          adminproto.ImportKeyRequest
	lastImportMnemonic     []byte // a copy, taken while the service had the phrase
	lastBackupRequest      adminproto.BackupIdentityRequest
	lastDeleteBackup       adminproto.DeleteBackupRequest
	lastInitializeStore    adminproto.InitializeStoreRequest
	lastChangePassphrase   adminproto.ChangeStorePassphraseRequest
	lastPreviewRestore     adminproto.PreviewRestoreRequest
	lastRestoreBackup      adminproto.RestoreBackupRequest
	lastRollbackRestore    adminproto.RollbackRestoreRequest
	lastCheckPolicy        adminproto.CheckPolicyRequest
	lastApplyPolicy        adminproto.ApplyPolicyRequest
	listLibraryResult      adminproto.ListLibraryTemplatesResult
	installResult          adminproto.InstallLibraryTemplateResult
	listInstalledResult    adminproto.ListInstalledTemplatesResult
	showInstalledResult    adminproto.ShowInstalledTemplateResult
	showLibraryResult      adminproto.ShowLibraryTemplateResult
	importInstalledResult  adminproto.ImportInstalledTemplateResult
	removeInstalledResult  adminproto.RemoveInstalledTemplateResult
	activateResult         adminproto.ActivateKeyTypeResult
	deactivateResult       adminproto.DeactivateKeyTypeResult
	keyTypesResult         adminproto.ListKeyTypesResult
	generateKeyResult      adminproto.GenerateKeyResult
	importKeyResult        adminproto.ImportKeyResult
	backupResult           adminproto.BackupIdentityResult
	listBackupsResult      adminproto.ListBackupsResult
	deleteBackupResult     adminproto.DeleteBackupResult
	initializeStoreResult  adminproto.InitializeStoreResult
	changePassphraseResult adminproto.ChangeStorePassphraseResult
	previewRestoreResult   adminproto.RestorePreviewResult
	restoreBackupResult    adminproto.RestoreBackupResult
	rollbackRestoreResult  adminproto.RollbackRestoreResult
	reconcileStoreResult   adminproto.ReconcileStoreResult
	getPolicyResult        adminproto.PolicyView
	checkPolicyResult      adminproto.CheckPolicyResult
	applyPolicyResult      adminproto.ApplyPolicyResult
}

func (s *stubServices) ProductRuntime() *productruntime.Runtime { return s.runtime }
func (s *stubServices) VerifyPassphrase(passphrase []byte) error {
	s.verifyCalls++
	if len(s.verifyErrs) == 0 {
		return nil
	}
	err := s.verifyErrs[0]
	s.verifyErrs = s.verifyErrs[1:]
	return err
}
func (s *stubServices) UnlockIdentity(passphrase []byte) (bool, int, string, string) {
	s.unlockCalls++
	return s.unlockOK, 0, s.unlockErrMsg, s.unlockCode
}
func (s *stubServices) InitializeStore(req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult {
	s.initializeStoreCalls++
	s.lastInitializeStore = adminproto.InitializeStoreRequest{
		Passphrase: append([]byte(nil), req.Passphrase...),
	}
	return s.initializeStoreResult
}
func (s *stubServices) ChangeStorePassphrase(_ context.Context, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
	s.changePassphraseCalls++
	s.lastChangePassphrase = adminproto.ChangeStorePassphraseRequest{
		CurrentPassphrase: append([]byte(nil), req.CurrentPassphrase...),
		NewPassphrase:     append([]byte(nil), req.NewPassphrase...),
	}
	return s.changePassphraseResult
}
func (s *stubServices) NewSessionIdentity(method string) *auth.Identity {
	if s.newIdentity != nil {
		return s.newIdentity
	}
	return auth.NewProductIdentity(method)
}
func (s *stubServices) EnrolledKeys() []protocol.EnrolledKeyInfo { return nil }
func (s *stubServices) RevokeEnrolledKey(SessionContext, string) (int, error) {
	return 0, nil
}
func (s *stubServices) RevokeAllEnrolledKeys(SessionContext) (int, int, error) { return 0, 0, nil }
func (s *stubServices) PendingEnrollments() []protocol.PendingEnrollmentInfo   { return nil }
func (s *stubServices) ApproveEnrollment(SessionContext, string, string) (string, error) {
	return "", nil
}
func (s *stubServices) RejectEnrollment(SessionContext, string) error { return nil }
func (s *stubServices) ImportClientKey(SessionContext, string, string) (ImportedClientKey, error) {
	return ImportedClientKey{}, nil
}
func (s *stubServices) BuildAdminSettings() adminproto.AdminSettings {
	return adminproto.AdminSettings{}
}
func (s *stubServices) UpdateAdminSetting(req adminproto.UpdateAdminSettingRequest) error {
	return nil
}
func (s *stubServices) GetPolicy() adminproto.PolicyView {
	s.getPolicyCalls++
	return s.getPolicyResult
}
func (s *stubServices) GetPolicyDocumentAt(req adminproto.GetPolicyDocumentRequest) adminproto.PolicyDocumentResult {
	return adminproto.PolicyDocumentResult{Success: true, Key: req.Key, Document: "{}"}
}
func (s *stubServices) GetPolicyContext() adminproto.PolicyContextView {
	return adminproto.PolicyContextView{Success: true}
}
func (s *stubServices) CheckPolicy(req adminproto.CheckPolicyRequest) adminproto.CheckPolicyResult {
	s.checkPolicyCalls++
	s.lastCheckPolicy = req
	return s.checkPolicyResult
}
func (s *stubServices) ApplyPolicy(req adminproto.ApplyPolicyRequest) adminproto.ApplyPolicyResult {
	s.applyPolicyCalls++
	s.lastApplyPolicy = req
	return s.applyPolicyResult
}
func (s *stubServices) ListASASet() adminproto.ListASASetResult {
	return adminproto.ListASASetResult{}
}
func (s *stubServices) LookupASA(req adminproto.LookupASARequest) adminproto.LookupASAResult {
	return adminproto.LookupASAResult{}
}
func (s *stubServices) AddASA(req adminproto.AddASARequest) adminproto.AddASAResult {
	s.addASACalls++
	return s.addASAResult
}
func (s *stubServices) RemoveASA(req adminproto.RemoveASARequest) adminproto.RemoveASAResult {
	s.removeASACalls++
	return s.removeASAResult
}
func (s *stubServices) ListKeys() ([]adminproto.KeyInfo, error) {
	return nil, nil
}
func (s *stubServices) GetKeyDetails(req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult {
	return adminproto.GetKeyDetailsResult{}
}
func (s *stubServices) PrepareGenerateKey(req adminproto.PrepareGenerateKeyRequest) adminproto.PrepareGenerateKeyResult {
	s.prepareGenerateCalls++
	s.lastPrepareGenerate = req
	return s.prepareGenerateResult
}
func (s *stubServices) GenerateKey(ctx context.Context, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult {
	s.generateKeyCalls++
	s.lastGenerateKeyContext = ctx
	s.lastGenerateKey = req
	return s.generateKeyResult
}
func (s *stubServices) DeleteKey(_ context.Context, req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult {
	return adminproto.DeleteKeyResult{}
}
func (s *stubServices) ImportKey(_ context.Context, req adminproto.ImportKeyRequest) adminproto.ImportKeyResult {
	s.importKeyCalls++
	s.lastImportKey = req
	s.lastImportMnemonic = append([]byte(nil), req.Mnemonic...)
	return s.importKeyResult
}
func (s *stubServices) BackupIdentity(req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult {
	s.backupCalls++
	s.lastBackupRequest = adminproto.BackupIdentityRequest{
		ExportPassphrase: append([]byte(nil), req.ExportPassphrase...),
		Addresses:        append([]string(nil), req.Addresses...),
	}
	return s.backupResult
}
func (s *stubServices) ListBackups() adminproto.ListBackupsResult {
	s.listBackupsCalls++
	return s.listBackupsResult
}
func (s *stubServices) DeleteBackup(req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult {
	s.deleteBackupCalls++
	s.lastDeleteBackup = req
	return s.deleteBackupResult
}
func (s *stubServices) BeginBackupImport(adminproto.BeginBackupImportRequest) adminproto.BeginBackupImportResult {
	s.beginBackupImportCalls++
	return adminproto.BeginBackupImportResult{}
}
func (s *stubServices) AppendBackupImport(adminproto.AppendBackupImportRequest) adminproto.AppendBackupImportResult {
	s.appendBackupImportCalls++
	return adminproto.AppendBackupImportResult{}
}
func (s *stubServices) CommitBackupImport(req adminproto.CommitBackupImportRequest) adminproto.CommitBackupImportResult {
	s.commitBackupImportCalls++
	s.lastCommitBackupImport = req
	s.lastCommitBackupImport.ExportPassphrase = append([]byte(nil), req.ExportPassphrase...)
	return s.commitBackupImportResult
}
func (*stubServices) AbortBackupImport(adminproto.AbortBackupImportRequest) adminproto.AbortBackupImportResult {
	return adminproto.AbortBackupImportResult{}
}

func (s *stubServices) ReadBackupChunk(adminproto.ReadBackupChunkRequest) adminproto.ReadBackupChunkResult {
	s.readBackupChunkCalls++
	return s.readBackupChunkResult
}
func (s *stubServices) PreviewRestore(req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult {
	s.previewRestoreCalls++
	s.lastPreviewRestore = adminproto.PreviewRestoreRequest{
		ArchivePath:      req.ArchivePath,
		ExportPassphrase: append([]byte(nil), req.ExportPassphrase...),
	}
	return s.previewRestoreResult
}
func (s *stubServices) RestoreBackup(req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult {
	s.restoreBackupCalls++
	s.lastRestoreBackup = adminproto.RestoreBackupRequest{
		OperationID:      req.OperationID,
		ArchivePath:      req.ArchivePath,
		Addresses:        append([]string(nil), req.Addresses...),
		ExportPassphrase: append([]byte(nil), req.ExportPassphrase...),
		ReplaceExisting:  req.ReplaceExisting,
	}
	return s.restoreBackupResult
}
func (s *stubServices) RollbackRestore(req adminproto.RollbackRestoreRequest) adminproto.RollbackRestoreResult {
	s.rollbackRestoreCalls++
	s.lastRollbackRestore = req
	return s.rollbackRestoreResult
}
func (s *stubServices) ReconcileStore() adminproto.ReconcileStoreResult {
	s.reconcileStoreCalls++
	return s.reconcileStoreResult
}
func (s *stubServices) ListLibraryTemplates() adminproto.ListLibraryTemplatesResult {
	s.listLibraryCalls++
	return s.listLibraryResult
}
func (s *stubServices) InstallLibraryTemplate(req adminproto.InstallLibraryTemplateRequest) adminproto.InstallLibraryTemplateResult {
	s.installLibraryCalls++
	s.lastInstallTemplate = req
	return s.installResult
}
func (s *stubServices) ListInstalledTemplates() adminproto.ListInstalledTemplatesResult {
	s.listInstalledCalls++
	return s.listInstalledResult
}
func (s *stubServices) ShowInstalledTemplate(req adminproto.ShowInstalledTemplateRequest) adminproto.ShowInstalledTemplateResult {
	s.showInstalledCalls++
	s.lastShowInstalled = req
	return s.showInstalledResult
}
func (s *stubServices) ShowLibraryTemplate(req adminproto.ShowLibraryTemplateRequest) adminproto.ShowLibraryTemplateResult {
	s.showLibraryCalls++
	s.lastShowLibrary = req
	return s.showLibraryResult
}
func (s *stubServices) ImportInstalledTemplate(req adminproto.ImportInstalledTemplateRequest) adminproto.ImportInstalledTemplateResult {
	s.importInstalledCalls++
	s.lastImportInstalled = adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: append([]byte(nil), req.TemplateYAML...),
	}
	return s.importInstalledResult
}
func (s *stubServices) RemoveInstalledTemplate(req adminproto.RemoveInstalledTemplateRequest) adminproto.RemoveInstalledTemplateResult {
	s.removeInstalledCalls++
	s.lastRemoveInstalled = req
	return s.removeInstalledResult
}
func (s *stubServices) ActivateKeyType(req adminproto.ActivateKeyTypeRequest) adminproto.ActivateKeyTypeResult {
	s.activateKeyTypeCalls++
	s.lastActivateKeyType = req
	return s.activateResult
}
func (s *stubServices) DeactivateKeyType(req adminproto.DeactivateKeyTypeRequest) adminproto.DeactivateKeyTypeResult {
	s.deactivateKeyTypeCalls++
	s.lastDeactivateKeyType = req
	return s.deactivateResult
}
func (s *stubServices) ListKeyTypes() adminproto.ListKeyTypesResult {
	s.listKeyTypesCalls++
	return s.keyTypesResult
}
func (s stubServices) deps() SessionDeps {
	return SessionDeps{
		Product:  &s,
		Settings: &s,
		Keys:     &s,
	}
}

func (s *stubServices) templateDeps() SessionDeps {
	return SessionDeps{
		Product:   s,
		Settings:  s,
		Keys:      s,
		Templates: s,
	}
}

func (s *stubServices) backupDeps() SessionDeps {
	return SessionDeps{
		Product: s,
		Backups: s,
	}
}

func TestSessionAuthenticateSuccess(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()

	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("secret"),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, stubServices{
		runtime:     ir,
		unlockOK:    true,
		newIdentity: auth.NewProductIdentity("ipc-passphrase"),
	}.deps(), OriginLocal)

	if session.AuthenticateOutcome() != AuthOutcomeAuthenticated {
		t.Fatal("authenticated = false, want true")
	}
	if session.State() != StateAuthenticated {
		t.Fatalf("State() = %v, want %v", session.State(), StateAuthenticated)
	}
	if session.BoundRuntime() != ir {
		t.Fatal("BoundRuntime() != resolved runtime")
	}
	if session.Identity() == nil {
		t.Fatal("Identity() = nil, want non-nil")
	}
	sessionCtx := session.SessionContext()
	if sessionCtx.SessionID == "" {
		t.Fatal("SessionContext().SessionID is empty")
	}
	if sessionCtx.AuthMethod != "ipc-passphrase" {
		t.Fatalf("SessionContext().AuthMethod = %q, want ipc-passphrase", sessionCtx.AuthMethod)
	}
	if sessionCtx.RemoteAddr != conn.RemoteAddr() {
		t.Fatalf("SessionContext().RemoteAddr = %q, want the connection's %q", sessionCtx.RemoteAddr, conn.RemoteAddr())
	}
	if sessionCtx.AdminPrincipal.ID != auth.SystemProductAdminPrincipalID {
		t.Fatalf("SessionContext().AdminPrincipal.ID = %q, want %q", sessionCtx.AdminPrincipal.ID, auth.SystemProductAdminPrincipalID)
	}
	if sessionCtx.RequesterPrincipal.ID != sessionCtx.AdminPrincipal.ID {
		t.Fatalf("SessionContext().RequesterPrincipal.ID = %q, want %q", sessionCtx.RequesterPrincipal.ID, sessionCtx.AdminPrincipal.ID)
	}
	if sessionCtx.ApproverPrincipal.ID != sessionCtx.AdminPrincipal.ID {
		t.Fatalf("SessionContext().ApproverPrincipal.ID = %q, want %q", sessionCtx.ApproverPrincipal.ID, sessionCtx.AdminPrincipal.ID)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("write count = %d, want 2", len(conn.writes))
	}

	var authReq protocol.AuthRequiredMessage
	if err := json.Unmarshal(conn.writes[0], &authReq); err != nil {
		t.Fatal(err)
	}
	if authReq.Type != protocol.MsgTypeAuthRequired {
		t.Fatalf("first write type = %q, want %q", authReq.Type, protocol.MsgTypeAuthRequired)
	}

	var result protocol.AuthResultMessage
	if err := json.Unmarshal(conn.writes[1], &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success {
		t.Fatal("auth result success = false, want true")
	}
}

func TestSessionAuthenticateOnlyKeepsLockedRuntimeLocked(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	authMsg, err := protocol.MarshalAdminMessage(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeAuthOnly},
		Passphrase:      protocol.NewSensitiveBytes("secret"),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := &stubServices{runtime: ir, unlockOK: true, newIdentity: auth.NewProductIdentity("ipc-passphrase")}
	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, SessionDeps{Product: svc}, OriginLocal)

	if session.AuthenticateOutcome() != AuthOutcomeAuthenticated {
		t.Fatal("authenticated = false, want authenticate-only success")
	}
	if svc.unlockCalls != 0 {
		t.Fatalf("UnlockIdentity calls = %d, want 0", svc.unlockCalls)
	}
	if ir.IsUnlocked() {
		t.Fatal("authenticate-only session unlocked the runtime")
	}
	if session.BoundRuntime() != ir {
		t.Fatal("authenticate-only session was not bound")
	}
	if !session.AuthenticatedOnly() {
		t.Fatal("authenticate-only session did not retain its restricted session mode")
	}
}

func TestAuthOnlyDispatchRejectsMutationAndPinsPublicReadAllowlist(t *testing.T) {
	wantAllowed := map[string]bool{
		protocol.MsgTypeGetAdminSettings:       true,
		protocol.MsgTypeListCosignerReferences: true,
		protocol.MsgTypeGetCosignerReference:   true,
		protocol.MsgTypeExportCosignerPublic:   true,
		protocol.MsgTypeListGenerations:        true,
		protocol.MsgTypeListEnrolledKeys:       true,
		protocol.MsgTypeListPendingEnrollments: true,
	}
	if len(authOnlyDispatchTypes) != len(wantAllowed) {
		t.Fatalf("auth_only allowlist size = %d, want %d", len(authOnlyDispatchTypes), len(wantAllowed))
	}
	for messageType := range wantAllowed {
		if !authOnlyDispatchTypes[messageType] {
			t.Errorf("auth_only allowlist missing %q", messageType)
		}
	}

	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{}, OriginLocal)
	session.authenticatedOnly = true
	raw := []byte(`{"kind":"request","type":"activate_key_type","id":"mutate-1"}`)
	session.Dispatch(raw)
	if len(conn.writes) != 1 {
		t.Fatalf("writes = %d, want one authorization error", len(conn.writes))
	}
	var result protocol.ErrorMessage
	if err := json.Unmarshal(conn.writes[0], &result); err != nil {
		t.Fatal(err)
	}
	if result.Code != protocol.ErrCodeAuthorizationDenied {
		t.Fatalf("error code = %q, want %q", result.Code, protocol.ErrCodeAuthorizationDenied)
	}
}

func TestSessionAuthenticateOutcomeHandlesLocalInitialize(t *testing.T) {
	initMsg, err := protocol.MarshalAdminMessage(protocol.InitializeStoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeInitializeStore, ID: "init-1"},
		Passphrase:  protocol.NewSensitiveBytes("new-passphrase"),
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := &stubServices{
		initializeStoreResult: adminproto.InitializeStoreResult{
			Success:     true,
			MetadataDir: "/data/identities/default",
		},
	}
	conn := &queueConn{reads: [][]byte{initMsg}}
	session := NewSession(conn, SessionDeps{Product: svc}, OriginLocal)

	if got := session.AuthenticateOutcome(); got != AuthOutcomeBootstrapHandled {
		t.Fatalf("AuthenticateOutcome() = %v, want %v", got, AuthOutcomeBootstrapHandled)
	}
	if string(svc.lastInitializeStore.Passphrase) != "new-passphrase" {
		t.Fatalf("InitializeStore passphrase = %q, want new-passphrase", string(svc.lastInitializeStore.Passphrase))
	}
	if len(conn.writes) != 2 {
		t.Fatalf("writes = %d, want auth_required and initialize result", len(conn.writes))
	}
	var result protocol.InitializeStoreResultMessage
	if err := json.Unmarshal(conn.writes[1], &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !result.Success || result.MetadataDir != "/data/identities/default" {
		t.Fatalf("initialize result = %#v", result)
	}
}

func TestSessionAuthenticateOutcomeRejectsInitializeAfterNodeFailure(t *testing.T) {
	initMsg, err := protocol.MarshalAdminMessage(protocol.InitializeStoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeInitializeStore, ID: "init-1"},
		Passphrase:  protocol.NewSensitiveBytes("new-passphrase"),
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := &stubServices{}
	conn := &queueConn{reads: [][]byte{initMsg}}
	session := NewSession(conn, SessionDeps{
		Product: svc,
		NodeFailure: func() error {
			return productruntime.ErrNodeFailClosed
		},
	}, OriginLocal)

	if got := session.AuthenticateOutcome(); got != AuthOutcomeBootstrapHandled {
		t.Fatalf("AuthenticateOutcome() = %v, want %v", got, AuthOutcomeBootstrapHandled)
	}
	if svc.initializeStoreCalls != 0 {
		t.Fatalf("InitializeStore calls = %d, want 0", svc.initializeStoreCalls)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("writes = %d, want auth_required and initialize result", len(conn.writes))
	}
	var result protocol.InitializeStoreResultMessage
	if err := json.Unmarshal(conn.writes[1], &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.ID != "init-1" || result.Code != protocol.ErrCodeNodeFailClosed {
		t.Fatalf("initialize result = %#v, want node-fail-closed response for init-1", result)
	}
}

func TestSessionDispatchInvalidTypedRequestPreservesRequestID(t *testing.T) {
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{}, OriginLocal)
	raw := []byte(`{"kind":"request","type":"generate_key","id":"gen-1","key_type":123}`)

	session.Dispatch(raw)

	msg := decodeProtocolError(t, conn)
	if msg.ID != "gen-1" {
		t.Fatalf("error id = %q, want gen-1", msg.ID)
	}
	if msg.Code != protocol.ErrCodeInvalidRequest {
		t.Fatalf("error code = %q, want %q", msg.Code, protocol.ErrCodeInvalidRequest)
	}
	if msg.Error != "invalid generate key message" {
		t.Fatalf("error = %q, want invalid generate key message", msg.Error)
	}
}

func TestSessionDispatchRejectsNonRequestEnvelope(t *testing.T) {
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{}, OriginLocal)
	raw := []byte(`{"kind":"response","type":"generate_key","id":"gen-1"}`)

	session.Dispatch(raw)

	msg := decodeProtocolError(t, conn)
	if msg.ID != "gen-1" {
		t.Fatalf("error id = %q, want gen-1", msg.ID)
	}
	if msg.Code != protocol.ErrCodeInvalidRequest {
		t.Fatalf("error code = %q, want %q", msg.Code, protocol.ErrCodeInvalidRequest)
	}
	if msg.Error != "expected request message" {
		t.Fatalf("error = %q, want expected request message", msg.Error)
	}
}

func TestSessionDispatchAdminSettingsRequestPreservesRequestID(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()

	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{
		Product:  svc,
		Settings: svc,
	}, OriginLocal)
	session.Bind(auth.NewProductIdentity("test"), ir)

	session.Dispatch([]byte(`{"kind":"request","type":"get_admin_settings","id":"settings-1"}`))
	var adminSettings protocol.AdminSettingsMessage
	decodeOnlyMessage(t, conn, &adminSettings)
	if adminSettings.ID != "settings-1" {
		t.Fatalf("admin settings id = %q, want settings-1", adminSettings.ID)
	}
}

func TestSessionDispatchRejectsPreviouslyAuthenticatedAdminAfterNodeFailure(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{
		Keys: svc,
		NodeFailure: func() error {
			return productruntime.ErrNodeFailClosed
		},
	}, OriginLocal)
	session.Bind(auth.NewProductIdentity("test"), ir)

	session.Dispatch([]byte(`{"kind":"request","type":"list_keys","id":"keys-1"}`))
	msg := decodeProtocolError(t, conn)
	if msg.ID != "keys-1" || msg.Code != protocol.ErrCodeNodeFailClosed {
		t.Fatalf("error = %#v, want node-fail-closed response for keys-1", msg)
	}
}

func TestSessionAuthenticateBindsProductRuntime(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()

	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("secret"),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	svc := &stubServices{
		runtime:     ir,
		unlockOK:    true,
		newIdentity: &auth.Identity{ID: "alice", Type: "service", Method: "ssh-passphrase"},
	}
	session := NewSession(conn, svc.templateDeps(), OriginLocal)

	if session.AuthenticateOutcome() != AuthOutcomeAuthenticated {
		t.Fatal("authenticated = false, want true")
	}
	if got := session.Identity(); got == nil || got.ID != "alice" {
		t.Fatalf("authenticated principal = %#v, want alice", got)
	}
}

func TestSessionAuthenticateRejectsUnknownFieldBeforePassphrase(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})

	authMsg := []byte(`{"kind":"request","type":"auth","passphrase":"secret","unexpected_selector":"bob","protocol_version":8}`)

	conn := &queueConn{reads: [][]byte{authMsg}}
	svc := &stubServices{
		runtime:  ir,
		unlockOK: true,
	}
	session := NewSession(conn, svc.templateDeps(), OriginLocal)

	if session.AuthenticateOutcome() == AuthOutcomeAuthenticated {
		t.Fatal("authenticated = true, want false")
	}
	if svc.verifyCalls != 0 {
		t.Fatalf("VerifyPassphrase calls = %d, want 0", svc.verifyCalls)
	}
	if svc.unlockCalls != 0 {
		t.Fatalf("UnlockIdentity calls = %d, want 0", svc.unlockCalls)
	}
	if ir.IsUnlocked() {
		t.Fatal("mismatched prebound identity unlocked runtime")
	}
	if len(conn.writes) != 2 {
		t.Fatalf("write count = %d, want 2", len(conn.writes))
	}

	var result protocol.AuthResultMessage
	if err := json.Unmarshal(conn.writes[1], &result); err != nil {
		t.Fatal(err)
	}
	if result.Success || result.Code != protocol.ErrCodeInvalidAuthMessage || result.Error != "invalid auth message format" {
		t.Fatalf("auth result = %+v, want unknown-field rejection", result)
	}
}

func TestSessionAuthenticateRejectsOldVersionBeforeUnknownField(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})

	authMsg := []byte(`{"kind":"request","type":"auth","passphrase":"secret","unexpected_selector":"alice","protocol_version":4}`)

	conn := &queueConn{reads: [][]byte{authMsg}}
	svc := &stubServices{
		runtime:  ir,
		unlockOK: true,
	}
	session := NewSession(conn, svc.templateDeps(), OriginLocal)

	if session.AuthenticateOutcome() == AuthOutcomeAuthenticated {
		t.Fatal("authenticated = true, want false")
	}
	if svc.verifyCalls != 0 {
		t.Fatalf("VerifyPassphrase calls = %d, want 0", svc.verifyCalls)
	}
	if svc.unlockCalls != 0 {
		t.Fatalf("UnlockIdentity calls = %d, want 0", svc.unlockCalls)
	}

	var result protocol.AuthResultMessage
	if err := json.Unmarshal(conn.writes[1], &result); err != nil {
		t.Fatal(err)
	}
	if result.Success || result.Code != protocol.ErrCodeInvalidAuthMessage || result.Error != "admin protocol version mismatch: client=4 server=8" {
		t.Fatalf("auth result = %+v, want version-first rejection", result)
	}
}

func TestSessionAuthenticateRetriesInvalidPassphrase(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()

	msg1, _ := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("wrong"),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})
	msg2, _ := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("right"),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})

	conn := &queueConn{reads: [][]byte{msg1, msg2}}
	session := NewSession(conn, stubServices{
		runtime:    ir,
		verifyErrs: []error{fmt.Errorf("verify: %w", algocrypto.ErrInvalidPassphrase), nil},
		unlockOK:   true,
	}.deps(), OriginLocal)

	if session.AuthenticateOutcome() != AuthOutcomeAuthenticated {
		t.Fatal("authenticated = false, want true")
	}
	if len(conn.writes) != 3 {
		t.Fatalf("write count = %d, want 3", len(conn.writes))
	}

	var firstResult protocol.AuthResultMessage
	if err := json.Unmarshal(conn.writes[1], &firstResult); err != nil {
		t.Fatal(err)
	}
	if firstResult.Success || firstResult.Error != "invalid passphrase" || firstResult.Code != protocol.ErrCodeInvalidPassphrase {
		t.Fatalf("first result = %+v, want invalid passphrase failure", firstResult)
	}

	var secondResult protocol.AuthResultMessage
	if err := json.Unmarshal(conn.writes[2], &secondResult); err != nil {
		t.Fatal(err)
	}
	if !secondResult.Success {
		t.Fatal("second auth result success = false, want true")
	}
}

// A store root the signer cannot open fails every passphrase, so the login
// says so and ends rather than asking for the passphrase again, and nothing
// is unlocked. The cause stays in the signer log, out of the pre-auth reply.
func TestSessionAuthenticateEndsOnADamagedStoreRoot(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	first := mustAuthFrame(t, "right-secret", "")
	second := mustAuthFrame(t, "right-secret", "")
	conn := &queueConn{reads: [][]byte{first, second}}
	svc := &stubServices{
		runtime:    ir,
		verifyErrs: []error{errors.New("read store root: open store-root.enc: permission denied")},
		unlockOK:   true,
	}
	session := NewSession(conn, svc.templateDeps(), OriginLocal)

	if got := session.AuthenticateOutcome(); got != AuthOutcomeFailed {
		t.Fatalf("AuthenticateOutcome() = %v, want AuthOutcomeFailed", got)
	}
	if svc.verifyCalls != 1 || svc.unlockCalls != 0 {
		t.Fatalf("VerifyPassphrase calls = %d, UnlockIdentity calls = %d; want one check and no unlock", svc.verifyCalls, svc.unlockCalls)
	}
	if len(conn.reads) != 1 {
		t.Fatalf("unread login frames = %d, want the second attempt left unread", len(conn.reads))
	}
	var result protocol.AuthResultMessage
	if err := json.Unmarshal(conn.writes[1], &result); err != nil {
		t.Fatal(err)
	}
	if result.Success || result.Code != protocol.ErrCodeAuthenticationFailed {
		t.Fatalf("auth result = %+v, want authentication_failed", result)
	}
	if result.Error == "invalid passphrase" || strings.Contains(result.Error, "permission denied") {
		t.Fatalf("auth result error = %q, want the store-root failure without its cause", result.Error)
	}
	if !isZeroedFrame(first) {
		t.Fatalf("login frame left as %q", first)
	}
}

func TestSessionAuthenticateMissingProductRuntimeIsGeneric(t *testing.T) {
	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("secret"),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, stubServices{}.deps(), OriginLocal)

	if session.AuthenticateOutcome() == AuthOutcomeAuthenticated {
		t.Fatal("authenticated = true, want false")
	}
	if len(conn.writes) != 2 {
		t.Fatalf("write count = %d, want 2", len(conn.writes))
	}

	var result protocol.AuthResultMessage
	if err := json.Unmarshal(conn.writes[1], &result); err != nil {
		t.Fatal(err)
	}
	if result.Success || result.Error != "authentication failed" || result.Code != protocol.ErrCodeAuthenticationFailed {
		t.Fatalf("auth result = %+v, want generic authentication failure", result)
	}
}

func TestSessionBindUpdatesSessionContext(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{}, OriginLocal)

	principal := &auth.Identity{
		ID:     "admin-1",
		Type:   "admin",
		Method: "test-method",
		Metadata: map[string]string{
			"role": "operator",
		},
	}
	session.Bind(principal, ir)

	sessionCtx := session.SessionContext()
	if sessionCtx.AdminPrincipal.ID != "admin-1" {
		t.Fatalf("AdminPrincipal.ID = %q, want admin-1", sessionCtx.AdminPrincipal.ID)
	}
	if sessionCtx.AdminPrincipal.Metadata["role"] != "operator" {
		t.Fatalf("AdminPrincipal.Metadata[role] = %q, want operator", sessionCtx.AdminPrincipal.Metadata["role"])
	}
	if sessionCtx.AuthMethod != "ipc-passphrase" {
		t.Fatalf("AuthMethod = %q, want ipc-passphrase", sessionCtx.AuthMethod)
	}
	if sessionCtx.RemoteAddr != conn.RemoteAddr() {
		t.Fatalf("RemoteAddr = %q, want the connection's %q", sessionCtx.RemoteAddr, conn.RemoteAddr())
	}

	sessionCtx.AdminPrincipal.Metadata["role"] = "mutated"
	if got := session.SessionContext().AdminPrincipal.Metadata["role"]; got != "operator" {
		t.Fatalf("SessionContext returned mutable metadata, got %q", got)
	}
}

func TestHandleSignResponseCarriesApproverPrincipal(t *testing.T) {
	conn := &queueConn{}
	ir := productruntime.New(productruntime.Config{})
	got := make(chan signerapproval.SignResponse, 1)
	sent := make(chan string, 1)
	ir.SetApprovalCoordinator(signerapproval.New(
		func() bool { return true },
		func(req *signerapproval.SignRequest) bool {
			sent <- req.ID
			return true
		},
		nil,
	))
	go func() {
		response, err := ir.RequestSigningApprovalPrompt(context.Background(), signerapproval.Prompt{RequestID: "req-1", Address: "ADDR", TxnSender: "SENDER", Description: "desc"}, time.Second)
		if err != nil {
			got <- signerapproval.SignResponse{ID: "error", Reason: err.Error()}
			return
		}
		got <- response
	}()
	promptID := <-sent

	session := NewSession(conn, SessionDeps{}, OriginLocal)
	session.Bind(&auth.Identity{ID: "alice-admin", Type: "service", Method: "ssh-passphrase"}, ir)
	session.HandleSignResponse(&protocol.SignResponseMessage{
		BaseMessage: protocol.BaseMessage{ID: promptID},
		Approved:    true,
	})

	response := <-got
	if response.ID != promptID {
		t.Fatalf("response ID = %q, want the prompt's ID %q (reason %q)", response.ID, promptID, response.Reason)
	}
	if !response.Approved {
		t.Fatal("response approved = false, want true")
	}
	if response.ApproverPrincipal != "alice-admin" {
		t.Fatalf("ApproverPrincipal = %q, want alice-admin", response.ApproverPrincipal)
	}
}

// ExportKey mimics the service contract: a successful phrase leaves only
// through deliver and is cleared before the result returns.
func (s *stubServices) ExportKey(_ context.Context, req adminproto.ExportKeyRequest, deliver adminproto.ExportDelivery) adminproto.ExportKeyResult {
	s.exportCalls++
	result := s.exportResult
	if result.Success {
		if err := deliver(result); err != nil {
			result.Success, result.Code = false, "internal"
		}
	}
	protocol.SensitiveBytes(result.Mnemonic).Zero()
	result.Mnemonic = nil
	return result
}

func TestSessionAuthenticateOutcomeRefusesRemoteInitialize(t *testing.T) {
	initMsg, err := protocol.MarshalAdminMessage(protocol.InitializeStoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeInitializeStore, ID: "init-1"},
		Passphrase:  protocol.NewSensitiveBytes("new-passphrase"),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := &stubServices{}
	conn := &queueConn{reads: [][]byte{initMsg}}
	session := NewSession(conn, SessionDeps{Product: svc}, OriginRemote)

	if got := session.AuthenticateOutcome(); got != AuthOutcomeBootstrapHandled {
		t.Fatalf("AuthenticateOutcome() = %v, want %v", got, AuthOutcomeBootstrapHandled)
	}
	if svc.lastInitializeStore.Passphrase != nil {
		t.Fatal("InitializeStore ran for a remote session")
	}
	var result protocol.InitializeStoreResultMessage
	if err := json.Unmarshal(conn.writes[len(conn.writes)-1], &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Success || result.Code != protocol.ErrCodeAuthorizationDenied {
		t.Fatalf("result = %+v, want authorization_denied", result)
	}
}

func isZeroedFrame(frame []byte) bool {
	for _, b := range frame {
		if b != 0 {
			return false
		}
	}
	return len(frame) > 0
}

func mustAuthFrame(t *testing.T, passphrase string, extra string) []byte {
	t.Helper()
	frame, err := protocol.MarshalAdminMessage(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes(passphrase),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if extra != "" {
		frame = append(frame[:len(frame)-1:len(frame)-1], []byte(`,`+extra+`}`)...)
	}
	return frame
}

// Login frames carry the store passphrase as JSON text. Each is zeroed once
// handled: one with a wrong passphrase before the next attempt is read, the
// accepted one when the login returns.
func TestSessionAuthenticateZeroesLoginFrames(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()
	wrong := mustAuthFrame(t, "wrong-secret", "")
	right := mustAuthFrame(t, "right-secret", "")
	svc := &stubServices{runtime: ir, verifyErrs: []error{algocrypto.ErrInvalidPassphrase}, newIdentity: auth.NewProductIdentity("ipc-passphrase")}
	session := NewSession(&queueConn{reads: [][]byte{wrong, right}}, SessionDeps{Product: svc}, OriginLocal)

	if session.AuthenticateOutcome() != AuthOutcomeAuthenticated {
		t.Fatal("authenticated = false, want the second attempt to succeed")
	}
	if svc.verifyCalls != 2 {
		t.Fatalf("VerifyPassphrase calls = %d, want 2", svc.verifyCalls)
	}
	for name, frame := range map[string][]byte{"wrong": wrong, "accepted": right} {
		if !isZeroedFrame(frame) {
			t.Fatalf("%s login frame left as %q", name, frame)
		}
	}

	refused := mustAuthFrame(t, "refused-secret", `"unexpected":1`)
	session = NewSession(&queueConn{reads: [][]byte{refused}}, SessionDeps{Product: &stubServices{runtime: ir}}, OriginLocal)
	if session.AuthenticateOutcome() == AuthOutcomeAuthenticated {
		t.Fatal("AuthenticateOutcome() accepted an auth frame with an unknown field")
	}
	if !isZeroedFrame(refused) {
		t.Fatalf("refused login frame left as %q", refused)
	}
}

// An initialize_store frame read before login is zeroed once handled,
// including when it is refused before the store is touched.
func TestSessionPreAuthInitializeZeroesFrame(t *testing.T) {
	newFrame := func() []byte {
		frame, err := protocol.MarshalAdminMessage(protocol.InitializeStoreMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeInitializeStore, ID: "init-1"},
			Passphrase:  protocol.NewSensitiveBytes("new-passphrase"),
		})
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}

	handled := newFrame()
	svc := &stubServices{initializeStoreResult: adminproto.InitializeStoreResult{Success: true}}
	session := NewSession(&queueConn{reads: [][]byte{handled}}, SessionDeps{Product: svc}, OriginLocal)
	if got := session.AuthenticateOutcome(); got != AuthOutcomeBootstrapHandled || svc.initializeStoreCalls != 1 {
		t.Fatalf("AuthenticateOutcome() = %v with %d initialize calls", got, svc.initializeStoreCalls)
	}
	if !isZeroedFrame(handled) {
		t.Fatalf("initialize frame left as %q", handled)
	}

	refused := newFrame()
	remote := NewSession(&queueConn{}, SessionDeps{Product: &stubServices{}}, OriginRemote)
	if got := remote.handlePreAuthInitialize("init-1", refused); got != AuthOutcomeBootstrapHandled {
		t.Fatalf("handlePreAuthInitialize() = %v", got)
	}
	if !isZeroedFrame(refused) {
		t.Fatalf("refused initialize frame left as %q", refused)
	}
}

// A pre-login initialize_store whose decode fails after its passphrase was
// decoded (a later id of the wrong type) has that passphrase zeroed, and is
// refused as an invalid request.
func TestSessionPreAuthInitializeZeroesAPartlyDecodedPassphrase(t *testing.T) {
	var decoded [][]byte
	original := decodeInitializeStore
	decodeInitializeStore = func(raw []byte) (protocol.InitializeStoreMessage, error) {
		msg, err := original(raw)
		decoded = append(decoded, msg.Passphrase)
		return msg, err
	}
	t.Cleanup(func() { decodeInitializeStore = original })

	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{Product: svc}, OriginLocal)
	raw := []byte(`{"kind":"request","type":"initialize_store","passphrase":"partly-decoded","id":7}`)
	if got := session.handlePreAuthInitialize("init-1", raw); got != AuthOutcomeBootstrapHandled {
		t.Fatalf("handlePreAuthInitialize() = %v", got)
	}
	if len(decoded) != 1 || len(decoded[0]) == 0 || !isZeroedFrame(decoded[0]) {
		t.Fatalf("partly decoded passphrase left as %q", decoded)
	}
	var reply protocol.InitializeStoreResultMessage
	if svc.initializeStoreCalls != 0 || len(conn.writes) != 1 || json.Unmarshal(conn.writes[0], &reply) != nil || reply.Code != protocol.ErrCodeInvalidRequest {
		t.Fatalf("malformed initialize_store ran %d times, answered %q", svc.initializeStoreCalls, conn.writes)
	}
}

// A request whose decode fails after its passphrase was decoded (here, a
// later id of the wrong type) has that passphrase zeroed, and the request is
// refused as before.
func TestDecodeRequestZeroesPartialDecodeOnError(t *testing.T) {
	raw := []byte(`{"kind":"request","type":"unlock","passphrase":"partly-decoded","id":7}`)
	msg, err := decodeRequest[protocol.UnlockMessage](raw)
	if err == nil {
		t.Fatal("decodeRequest accepted a numeric id")
	}
	if len(msg.Passphrase) == 0 || !isZeroedFrame(msg.Passphrase) {
		t.Fatalf("partly decoded passphrase left as %q", []byte(msg.Passphrase))
	}

	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Product: &stubServices{}}, OriginLocal)
	session.Dispatch([]byte(`{"kind":"request","type":"unlock","id":"u","passphrase":7}`))
	var refusal protocol.ErrorMessage
	if len(conn.writes) != 1 || json.Unmarshal(conn.writes[0], &refusal) != nil || refusal.Code != protocol.ErrCodeInvalidRequest {
		t.Fatalf("malformed unlock answered with %q", conn.writes)
	}
}

// TestSessionAuthenticateAdminProtocolVersionRule pins what each
// protocol_version an auth frame carries leads to, and the auth_required
// frame the server sends first.
func TestSessionAuthenticateAdminProtocolVersionRule(t *testing.T) {
	tests := []struct {
		name    string
		version string // the auth frame's protocol_version, or "" for none
		wantErr string // "" when the frame authenticates
	}{
		{name: "current", version: `8`},
		{name: "older", version: `7`, wantErr: "admin protocol version mismatch: client=7 server=8"},
		{name: "newer", version: `9`, wantErr: "admin protocol version mismatch: client=9 server=8"},
		{name: "missing", wantErr: "admin protocol version mismatch: client=0 server=8"},
		{name: "major and minor", version: `{"major":8,"minor":0}`, wantErr: "invalid auth message format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ir := productruntime.New(productruntime.Config{})
			ir.SetUnlocked()
			frame := `{"kind":"request","type":"auth","passphrase":"secret"`
			if tt.version != "" {
				frame += `,"protocol_version":` + tt.version
			}
			frame += `}`
			conn := &queueConn{reads: [][]byte{[]byte(frame)}}
			svc := stubServices{
				runtime:     ir,
				unlockOK:    true,
				newIdentity: auth.NewProductIdentity("ipc-passphrase"),
			}
			session := NewSession(conn, svc.deps(), OriginLocal)

			authenticated := session.AuthenticateOutcome() == AuthOutcomeAuthenticated
			if len(conn.writes) != 2 {
				t.Fatalf("write count = %d, want 2", len(conn.writes))
			}
			if got := string(conn.writes[0]); got != `{"type":"auth_required","id":"","kind":"notification"}` {
				t.Fatalf("auth_required = %s", got)
			}
			var result protocol.AuthResultMessage
			if err := json.Unmarshal(conn.writes[1], &result); err != nil {
				t.Fatal(err)
			}
			if tt.wantErr == "" {
				if !authenticated || !result.Success {
					t.Fatalf("authenticated = %v, result = %+v, want success", authenticated, result)
				}
				return
			}
			if authenticated || result.Success || result.Code != protocol.ErrCodeInvalidAuthMessage || result.Error != tt.wantErr {
				t.Fatalf("authenticated = %v, result = %+v, want %q", authenticated, result, tt.wantErr)
			}
		})
	}
}
