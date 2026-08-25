// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
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
	policySnapshotCalls    int
	replacePolicyCalls     int
	validatePolicyCalls    int
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
	lastBackupRequest      adminproto.BackupIdentityRequest
	lastDeleteBackup       adminproto.DeleteBackupRequest
	lastInitializeStore    adminproto.InitializeStoreRequest
	lastChangePassphrase   adminproto.ChangeStorePassphraseRequest
	lastPreviewRestore     adminproto.PreviewRestoreRequest
	lastRestoreBackup      adminproto.RestoreBackupRequest
	lastRollbackRestore    adminproto.RollbackRestoreRequest
	lastPolicySnapshot     adminproto.PolicyTarget
	lastReplacePolicy      adminproto.ReplacePolicyRequest
	lastValidatePolicy     adminproto.ValidatePolicyRequest
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
	policySnapshotResult   adminproto.PolicySnapshot
	replacePolicyResult    adminproto.PolicySnapshot
	validatePolicyResult   adminproto.ValidatePolicyResult
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
func (s *stubServices) ChangeStorePassphrase(req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
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
func (s *stubServices) RevokeProductToken() error { return nil }
func (s *stubServices) BuildAdminSettings() adminproto.AdminSettings {
	return adminproto.AdminSettings{}
}
func (s *stubServices) UpdateAdminSetting(req adminproto.UpdateAdminSettingRequest) error {
	return nil
}
func (s *stubServices) BuildPolicySnapshot(target adminproto.PolicyTarget) adminproto.PolicySnapshot {
	s.policySnapshotCalls++
	s.lastPolicySnapshot = target
	if s.policySnapshotResult.Target == "" {
		s.policySnapshotResult.Target = target
	}
	return s.policySnapshotResult
}
func (s *stubServices) ReplacePolicy(req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot {
	s.replacePolicyCalls++
	s.lastReplacePolicy = req
	if s.replacePolicyResult.Target == "" {
		s.replacePolicyResult.Target = req.Target
	}
	return s.replacePolicyResult
}
func (s *stubServices) ValidatePolicy(req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult {
	s.validatePolicyCalls++
	s.lastValidatePolicy = req
	if s.validatePolicyResult.Target == "" {
		s.validatePolicyResult.Target = req.Target
	}
	return s.validatePolicyResult
}
func (s *stubServices) ListKeys() ([]adminproto.KeyInfo, error) {
	return nil, nil
}
func (s *stubServices) GetKeyDetails(req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult {
	return adminproto.GetKeyDetailsResult{}
}
func (s *stubServices) GenerateKey(ctx context.Context, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult {
	s.generateKeyCalls++
	s.lastGenerateKeyContext = ctx
	s.lastGenerateKey = req
	return s.generateKeyResult
}
func (s *stubServices) DeleteKey(req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult {
	return adminproto.DeleteKeyResult{}
}
func (s *stubServices) ImportKey(req adminproto.ImportKeyRequest) adminproto.ImportKeyResult {
	s.importKeyCalls++
	s.lastImportKey = req
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

func currentAdminProtocolVersion() *protocol.ProtocolVersion {
	version := protocol.CurrentAdminProtocolVersion()
	return &version
}

func TestSessionAuthenticateSuccess(t *testing.T) {
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetUnlocked()

	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("secret"),
		ProtocolVersion: currentAdminProtocolVersion(),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, stubServices{
		runtime:     ir,
		unlockOK:    true,
		newIdentity: auth.NewProductIdentity("ipc-passphrase"),
	}.deps())
	session.SetTransportInfo(TransportIPC, "unix:/tmp/aplane.sock")

	if !session.Authenticate() {
		t.Fatal("Authenticate() = false, want true")
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
	if sessionCtx.Transport != TransportIPC {
		t.Fatalf("SessionContext().Transport = %q, want %q", sessionCtx.Transport, TransportIPC)
	}
	if sessionCtx.RemoteAddr != "unix:/tmp/aplane.sock" {
		t.Fatalf("SessionContext().RemoteAddr = %q, want unix:/tmp/aplane.sock", sessionCtx.RemoteAddr)
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
	if authReq.ProtocolVersion != protocol.CurrentAdminProtocolVersion() {
		t.Fatalf("auth_required protocol_version = %+v, want %+v", authReq.ProtocolVersion, protocol.CurrentAdminProtocolVersion())
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
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	authMsg, err := protocol.MarshalAdminMessage(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeAuthOnly},
		Passphrase:      protocol.NewSensitiveBytes("secret"),
		ProtocolVersion: currentAdminProtocolVersion(),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := &stubServices{runtime: ir, unlockOK: true, newIdentity: auth.NewProductIdentity("ipc-passphrase")}
	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, SessionDeps{Product: svc})
	session.SetTransportInfo(TransportIPC, "unix:/tmp/aplane.sock")

	if !session.Authenticate() {
		t.Fatal("Authenticate() = false, want authenticate-only success")
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
		protocol.MsgTypeGetAdminSettings:     true,
		protocol.MsgTypeListSentryReferences: true,
		protocol.MsgTypeGetSentryReference:   true,
		protocol.MsgTypeExportSentryPublic:   true,
		protocol.MsgTypeListGenerations:      true,
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
	session := NewSession(conn, SessionDeps{})
	session.authenticatedOnly = true
	raw := []byte(`{"kind":"request","type":"activate_key_type","id":"mutate-1"}`)
	if !session.Dispatch(raw) {
		t.Fatal("Dispatch() = false, want handled authorization rejection")
	}
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
	session := NewSession(conn, SessionDeps{Product: svc})
	session.SetTransportInfo(TransportIPC, "unix:/tmp/aplane.sock")

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
	})
	session.SetTransportInfo(TransportIPC, "unix:/tmp/aplane.sock")

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
	session := NewSession(conn, SessionDeps{})
	raw := []byte(`{"kind":"request","type":"generate_key","id":"gen-1","key_type":123}`)

	if !session.Dispatch(raw) {
		t.Fatal("Dispatch() = false, want true")
	}

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
	session := NewSession(conn, SessionDeps{})
	raw := []byte(`{"kind":"response","type":"generate_key","id":"gen-1"}`)

	if !session.Dispatch(raw) {
		t.Fatal("Dispatch() = false, want true")
	}

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
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{
		Product:  svc,
		Settings: svc,
	})
	session.Bind(auth.NewProductIdentity("test"), ir)

	if !session.Dispatch([]byte(`{"kind":"request","type":"get_admin_settings","id":"settings-1"}`)) {
		t.Fatal("Dispatch(get_admin_settings) = false, want true")
	}
	var adminSettings protocol.AdminSettingsMessage
	decodeOnlyMessage(t, conn, &adminSettings)
	if adminSettings.ID != "settings-1" {
		t.Fatalf("admin settings id = %q, want settings-1", adminSettings.ID)
	}
}

func TestSessionDispatchRejectsPreviouslyAuthenticatedAdminAfterNodeFailure(t *testing.T) {
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{
		Keys: svc,
		NodeFailure: func() error {
			return productruntime.ErrNodeFailClosed
		},
	})
	session.Bind(auth.NewProductIdentity("test"), ir)

	if !session.Dispatch([]byte(`{"kind":"request","type":"list_keys","id":"keys-1"}`)) {
		t.Fatal("Dispatch(list_keys) = false, want handled fail-closed response")
	}
	msg := decodeProtocolError(t, conn)
	if msg.ID != "keys-1" || msg.Code != protocol.ErrCodeNodeFailClosed {
		t.Fatalf("error = %#v, want node-fail-closed response for keys-1", msg)
	}
}

func TestSessionAuthenticateBindsProductRuntime(t *testing.T) {
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetUnlocked()

	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("secret"),
		ProtocolVersion: currentAdminProtocolVersion(),
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
	session := NewSession(conn, svc.templateDeps())
	session.SetAuthMethod("ssh-passphrase")

	if !session.Authenticate() {
		t.Fatal("Authenticate() = false, want true")
	}
	if got := session.Identity(); got == nil || got.ID != "alice" {
		t.Fatalf("authenticated principal = %#v, want alice", got)
	}
}

func TestSessionAuthenticateRejectsUnknownFieldBeforePassphrase(t *testing.T) {
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})

	authMsg := []byte(`{"kind":"request","type":"auth","passphrase":"secret","unexpected_selector":"bob","protocol_version":{"major":5,"minor":0}}`)

	conn := &queueConn{reads: [][]byte{authMsg}}
	svc := &stubServices{
		runtime:  ir,
		unlockOK: true,
	}
	session := NewSession(conn, svc.templateDeps())
	session.SetAuthMethod("ssh-passphrase")

	if session.Authenticate() {
		t.Fatal("Authenticate() = true, want false")
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
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})

	authMsg := []byte(`{"kind":"request","type":"auth","passphrase":"secret","unexpected_selector":"alice","protocol_version":{"major":4,"minor":5}}`)

	conn := &queueConn{reads: [][]byte{authMsg}}
	svc := &stubServices{
		runtime:  ir,
		unlockOK: true,
	}
	session := NewSession(conn, svc.templateDeps())

	if session.Authenticate() {
		t.Fatal("Authenticate() = true, want false")
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
	if result.Success || result.Code != protocol.ErrCodeInvalidAuthMessage || result.Error != "admin protocol major version mismatch: client=4 server=5" {
		t.Fatalf("auth result = %+v, want version-first rejection", result)
	}
}

func TestSessionAuthenticateRetriesInvalidPassphrase(t *testing.T) {
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetUnlocked()

	msg1, _ := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("wrong"),
		ProtocolVersion: currentAdminProtocolVersion(),
	})
	msg2, _ := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("right"),
		ProtocolVersion: currentAdminProtocolVersion(),
	})

	conn := &queueConn{reads: [][]byte{msg1, msg2}}
	session := NewSession(conn, stubServices{
		runtime:    ir,
		verifyErrs: []error{errors.New("bad"), nil},
		unlockOK:   true,
	}.deps())

	if !session.Authenticate() {
		t.Fatal("Authenticate() = false, want true")
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

func TestSessionAuthenticateMissingProductRuntimeIsGeneric(t *testing.T) {
	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes("secret"),
		ProtocolVersion: currentAdminProtocolVersion(),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, stubServices{}.deps())

	if session.Authenticate() {
		t.Fatal("Authenticate() = true, want false")
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

func TestSessionAuthenticateRejectsAdminProtocolMajorMismatch(t *testing.T) {
	currentMajor := protocol.CurrentAdminProtocolVersion().Major
	tests := []struct {
		name  string
		major int
	}{
		{name: "older", major: currentMajor - 1},
		{name: "newer", major: currentMajor + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientVersion := protocol.ProtocolVersion{Major: tt.major}
			authMsg, err := json.Marshal(protocol.AuthMessage{
				BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
				Passphrase:      protocol.NewSensitiveBytes("secret"),
				ProtocolVersion: &clientVersion,
			})
			if err != nil {
				t.Fatal(err)
			}

			conn := &queueConn{reads: [][]byte{authMsg}}
			session := NewSession(conn, stubServices{}.deps())

			if session.Authenticate() {
				t.Fatal("Authenticate() = true, want false")
			}
			if len(conn.writes) != 2 {
				t.Fatalf("write count = %d, want 2", len(conn.writes))
			}

			var result protocol.AuthResultMessage
			if err := json.Unmarshal(conn.writes[1], &result); err != nil {
				t.Fatal(err)
			}
			if result.Success || result.Code != protocol.ErrCodeInvalidAuthMessage {
				t.Fatalf("auth result = %+v, want invalid auth protocol failure", result)
			}
			if !strings.Contains(result.Error, "admin protocol major version mismatch") {
				t.Fatalf("auth result error = %q, want major version mismatch", result.Error)
			}
		})
	}
}

func TestSessionAuthenticateRejectsMissingAdminProtocolVersion(t *testing.T) {
	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:  protocol.NewSensitiveBytes("secret"),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, stubServices{}.deps())

	if session.Authenticate() {
		t.Fatal("Authenticate() = true, want false")
	}

	var result protocol.AuthResultMessage
	if err := json.Unmarshal(conn.writes[1], &result); err != nil {
		t.Fatal(err)
	}
	if result.Success || result.Code != protocol.ErrCodeInvalidAuthMessage {
		t.Fatalf("auth result = %+v, want invalid auth protocol failure", result)
	}
	if !strings.Contains(result.Error, "admin protocol version is required") {
		t.Fatalf("auth result error = %q, want required-version failure", result.Error)
	}
}

func TestValidateAdminProtocolVersionAcceptsCurrentAndMinorSkew(t *testing.T) {
	current := protocol.CurrentAdminProtocolVersion()
	if ok, errMsg := validateAdminProtocolVersion(&current); !ok || errMsg != "" {
		t.Fatalf("current version rejected: ok=%v error=%q", ok, errMsg)
	}

	newerMinor := current
	newerMinor.Minor++
	if ok, errMsg := validateAdminProtocolVersion(&newerMinor); !ok || errMsg != "" {
		t.Fatalf("minor skew rejected: ok=%v error=%q", ok, errMsg)
	}
}

func TestSessionBindUpdatesSessionContext(t *testing.T) {
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{})
	session.SetAuthMethod("test-method")
	session.SetTransportInfo(TransportSSH, "10.0.0.1:2222")

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
	if sessionCtx.AuthMethod != "test-method" {
		t.Fatalf("AuthMethod = %q, want test-method", sessionCtx.AuthMethod)
	}
	if sessionCtx.Transport != TransportSSH {
		t.Fatalf("Transport = %q, want %q", sessionCtx.Transport, TransportSSH)
	}
	if sessionCtx.RemoteAddr != "10.0.0.1:2222" {
		t.Fatalf("RemoteAddr = %q, want 10.0.0.1:2222", sessionCtx.RemoteAddr)
	}

	sessionCtx.AdminPrincipal.Metadata["role"] = "mutated"
	if got := session.SessionContext().AdminPrincipal.Metadata["role"]; got != "operator" {
		t.Fatalf("SessionContext returned mutable metadata, got %q", got)
	}
}

func TestHandleSignResponseCarriesApproverPrincipal(t *testing.T) {
	conn := &queueConn{}
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	got := make(chan signerapproval.SignResponse, 1)
	sent := make(chan struct{}, 1)
	ir.SetApprovalCoordinator(signerapproval.New(
		func() bool { return true },
		func(req *signerapproval.SignRequest) bool {
			sent <- struct{}{}
			return true
		},
		nil,
		nil,
	))
	go func() {
		response, err := ir.RequestSigningApprovalResponse("req-1", "ADDR", "SENDER", "desc", 0, 0, nil, time.Second)
		if err != nil {
			got <- signerapproval.SignResponse{ID: "error", Reason: err.Error()}
			return
		}
		got <- response
	}()
	<-sent

	session := NewSession(conn, SessionDeps{})
	session.SetTransportInfo(TransportSSH, "10.0.0.1:2222")
	session.Bind(&auth.Identity{ID: "alice-admin", Type: "service", Method: "ssh-passphrase"}, ir)
	session.HandleSignResponse(&protocol.SignResponseMessage{
		BaseMessage: protocol.BaseMessage{ID: "req-1"},
		Approved:    true,
	})

	response := <-got
	if response.ID != "req-1" {
		t.Fatalf("response ID = %q, want req-1 (reason %q)", response.ID, response.Reason)
	}
	if !response.Approved {
		t.Fatal("response approved = false, want true")
	}
	if response.ApproverPrincipal != "alice-admin" {
		t.Fatalf("ApproverPrincipal = %q, want alice-admin", response.ApproverPrincipal)
	}
}
