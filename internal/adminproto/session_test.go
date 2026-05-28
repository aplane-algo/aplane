// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
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
	runtime      *identity.Runtime
	verifyErrs   []error
	unlockOK     bool
	unlockErrMsg string
	resolveErr   error
	newIdentity  *auth.Identity
	resolveIDs   []string
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
	changePassphraseCalls  int
	previewRestoreCalls    int
	restoreBackupCalls     int
	policySnapshotCalls    int
	replacePolicyCalls     int
	lastInstallTemplate    InstallLibraryTemplateRequest
	lastShowInstalled      ShowInstalledTemplateRequest
	lastShowLibrary        ShowLibraryTemplateRequest
	lastImportInstalled    ImportInstalledTemplateRequest
	lastRemoveInstalled    RemoveInstalledTemplateRequest
	lastActivateKeyType    ActivateKeyTypeRequest
	lastDeactivateKeyType  DeactivateKeyTypeRequest
	lastGenerateKeyContext context.Context
	lastGenerateKey        GenerateKeyRequest
	lastImportKey          ImportKeyRequest
	lastBackupRequest      BackupIdentityRequest
	lastDeleteBackup       DeleteBackupRequest
	lastInitializeStore    InitializeStoreRequest
	lastChangePassphrase   ChangeStorePassphraseRequest
	lastPreviewRestore     PreviewRestoreRequest
	lastRestoreBackup      RestoreBackupRequest
	lastReplacePolicy      ReplacePolicyRequest
	listLibraryResult      ListLibraryTemplatesResult
	installResult          InstallLibraryTemplateResult
	listInstalledResult    ListInstalledTemplatesResult
	showInstalledResult    ShowInstalledTemplateResult
	showLibraryResult      ShowLibraryTemplateResult
	importInstalledResult  ImportInstalledTemplateResult
	removeInstalledResult  RemoveInstalledTemplateResult
	activateResult         ActivateKeyTypeResult
	deactivateResult       DeactivateKeyTypeResult
	keyTypesResult         ListKeyTypesResult
	generateKeyResult      GenerateKeyResult
	importKeyResult        ImportKeyResult
	backupResult           BackupIdentityResult
	listBackupsResult      ListBackupsResult
	deleteBackupResult     DeleteBackupResult
	initializeStoreResult  InitializeStoreResult
	changePassphraseResult ChangeStorePassphraseResult
	previewRestoreResult   RestorePreviewResult
	restoreBackupResult    RestoreBackupResult
	policySnapshotResult   PolicySnapshot
	replacePolicyResult    PolicySnapshot
}

func (s *stubServices) ProductIdentityRuntime() *identity.Runtime { return s.runtime }
func (s *stubServices) ResolveIdentity(identityID string) (*identity.Runtime, error) {
	s.resolveIDs = append(s.resolveIDs, identityID)
	if s.resolveErr != nil {
		return nil, s.resolveErr
	}
	return s.runtime, nil
}
func (s *stubServices) VerifyPassphrase(ir *identity.Runtime, passphrase []byte) error {
	s.verifyCalls++
	if len(s.verifyErrs) == 0 {
		return nil
	}
	err := s.verifyErrs[0]
	s.verifyErrs = s.verifyErrs[1:]
	return err
}
func (s *stubServices) UnlockIdentity(ir *identity.Runtime, passphrase []byte) (bool, int, string) {
	s.unlockCalls++
	return s.unlockOK, 0, s.unlockErrMsg
}
func (s *stubServices) InitializeStore(req InitializeStoreRequest) InitializeStoreResult {
	s.lastInitializeStore = InitializeStoreRequest{
		Passphrase: append([]byte(nil), req.Passphrase...),
	}
	return s.initializeStoreResult
}
func (s *stubServices) ChangeStorePassphrase(ir *identity.Runtime, req ChangeStorePassphraseRequest) ChangeStorePassphraseResult {
	s.changePassphraseCalls++
	s.lastChangePassphrase = ChangeStorePassphraseRequest{
		CurrentPassphrase: append([]byte(nil), req.CurrentPassphrase...),
		NewPassphrase:     append([]byte(nil), req.NewPassphrase...),
	}
	return s.changePassphraseResult
}
func (s *stubServices) NewSessionIdentity(method string) *auth.Identity {
	if s.newIdentity != nil {
		return s.newIdentity
	}
	return auth.NewDefaultIdentity(method)
}
func (s *stubServices) RevokeTokenForIdentity(ir *identity.Runtime) error { return nil }
func (s *stubServices) BuildAdminSettings(ir *identity.Runtime) AdminSettings {
	return AdminSettings{}
}
func (s *stubServices) UpdateAdminSetting(ir *identity.Runtime, req UpdateAdminSettingRequest) error {
	return nil
}
func (s *stubServices) BuildPolicySettings(ir *identity.Runtime) PolicySettings {
	return PolicySettings{}
}
func (s *stubServices) BuildPolicySnapshot(ir *identity.Runtime) PolicySnapshot {
	s.policySnapshotCalls++
	if s.policySnapshotResult.IdentityID == "" {
		s.policySnapshotResult.IdentityID = ir.ID()
	}
	return s.policySnapshotResult
}
func (s *stubServices) ReplacePolicy(ir *identity.Runtime, req ReplacePolicyRequest) PolicySnapshot {
	s.replacePolicyCalls++
	s.lastReplacePolicy = req
	if s.replacePolicyResult.IdentityID == "" {
		s.replacePolicyResult.IdentityID = ir.ID()
	}
	return s.replacePolicyResult
}
func (s *stubServices) UpdatePolicySetting(ir *identity.Runtime, req UpdatePolicySettingRequest) error {
	return nil
}
func (s *stubServices) UpdatePolicyASAAmounts(ir *identity.Runtime, req UpdatePolicyASAAmountsRequest) error {
	return nil
}
func (s *stubServices) SearchASAMetadata(ir *identity.Runtime, req SearchASAMetadataRequest) ASAMetadataResults {
	return ASAMetadataResults{}
}
func (s *stubServices) ResolveASAMetadata(ir *identity.Runtime, req ResolveASAMetadataRequest) ASAMetadataResult {
	return ASAMetadataResult{}
}
func (s *stubServices) ListKeys(ir *identity.Runtime) ([]KeyInfo, error) {
	return nil, nil
}
func (s *stubServices) GetKeyDetails(ir *identity.Runtime, req GetKeyDetailsRequest) GetKeyDetailsResult {
	return GetKeyDetailsResult{}
}
func (s *stubServices) GenerateKey(ctx context.Context, ir *identity.Runtime, req GenerateKeyRequest) GenerateKeyResult {
	s.generateKeyCalls++
	s.lastGenerateKeyContext = ctx
	s.lastGenerateKey = req
	return s.generateKeyResult
}
func (s *stubServices) DeleteKey(ir *identity.Runtime, req DeleteKeyRequest) DeleteKeyResult {
	return DeleteKeyResult{}
}
func (s *stubServices) ImportKey(ir *identity.Runtime, req ImportKeyRequest) ImportKeyResult {
	s.importKeyCalls++
	s.lastImportKey = req
	return s.importKeyResult
}
func (s *stubServices) BackupIdentity(ir *identity.Runtime, req BackupIdentityRequest) BackupIdentityResult {
	s.backupCalls++
	s.lastBackupRequest = BackupIdentityRequest{
		ExportPassphrase: append([]byte(nil), req.ExportPassphrase...),
		Addresses:        append([]string(nil), req.Addresses...),
	}
	return s.backupResult
}
func (s *stubServices) ListBackups(ir *identity.Runtime) ListBackupsResult {
	s.listBackupsCalls++
	return s.listBackupsResult
}
func (s *stubServices) DeleteBackup(ir *identity.Runtime, req DeleteBackupRequest) DeleteBackupResult {
	s.deleteBackupCalls++
	s.lastDeleteBackup = req
	return s.deleteBackupResult
}
func (s *stubServices) PreviewRestore(ir *identity.Runtime, req PreviewRestoreRequest) RestorePreviewResult {
	s.previewRestoreCalls++
	s.lastPreviewRestore = PreviewRestoreRequest{
		ArchivePath:      req.ArchivePath,
		ExportPassphrase: append([]byte(nil), req.ExportPassphrase...),
	}
	return s.previewRestoreResult
}
func (s *stubServices) RestoreBackup(ir *identity.Runtime, req RestoreBackupRequest) RestoreBackupResult {
	s.restoreBackupCalls++
	s.lastRestoreBackup = RestoreBackupRequest{
		ArchivePath:      req.ArchivePath,
		Addresses:        append([]string(nil), req.Addresses...),
		Overwrite:        req.Overwrite,
		ExportPassphrase: append([]byte(nil), req.ExportPassphrase...),
	}
	return s.restoreBackupResult
}
func (s *stubServices) ListLibraryTemplates(ir *identity.Runtime) ListLibraryTemplatesResult {
	s.listLibraryCalls++
	return s.listLibraryResult
}
func (s *stubServices) InstallLibraryTemplate(ir *identity.Runtime, req InstallLibraryTemplateRequest) InstallLibraryTemplateResult {
	s.installLibraryCalls++
	s.lastInstallTemplate = req
	return s.installResult
}
func (s *stubServices) ListInstalledTemplates(ir *identity.Runtime) ListInstalledTemplatesResult {
	s.listInstalledCalls++
	return s.listInstalledResult
}
func (s *stubServices) ShowInstalledTemplate(ir *identity.Runtime, req ShowInstalledTemplateRequest) ShowInstalledTemplateResult {
	s.showInstalledCalls++
	s.lastShowInstalled = req
	return s.showInstalledResult
}
func (s *stubServices) ShowLibraryTemplate(ir *identity.Runtime, req ShowLibraryTemplateRequest) ShowLibraryTemplateResult {
	s.showLibraryCalls++
	s.lastShowLibrary = req
	return s.showLibraryResult
}
func (s *stubServices) ImportInstalledTemplate(ir *identity.Runtime, req ImportInstalledTemplateRequest) ImportInstalledTemplateResult {
	s.importInstalledCalls++
	s.lastImportInstalled = ImportInstalledTemplateRequest{
		TemplateYAML: append([]byte(nil), req.TemplateYAML...),
	}
	return s.importInstalledResult
}
func (s *stubServices) RemoveInstalledTemplate(ir *identity.Runtime, req RemoveInstalledTemplateRequest) RemoveInstalledTemplateResult {
	s.removeInstalledCalls++
	s.lastRemoveInstalled = req
	return s.removeInstalledResult
}
func (s *stubServices) ActivateKeyType(ir *identity.Runtime, req ActivateKeyTypeRequest) ActivateKeyTypeResult {
	s.activateKeyTypeCalls++
	s.lastActivateKeyType = req
	return s.activateResult
}
func (s *stubServices) DeactivateKeyType(ir *identity.Runtime, req DeactivateKeyTypeRequest) DeactivateKeyTypeResult {
	s.deactivateKeyTypeCalls++
	s.lastDeactivateKeyType = req
	return s.deactivateResult
}
func (s *stubServices) ListKeyTypes(ir *identity.Runtime) ListKeyTypesResult {
	s.listKeyTypesCalls++
	return s.keyTypesResult
}
func (s *stubServices) LogSessionConnected(identityID, remoteAddr, transport string) {
}
func (s *stubServices) LogSessionDisconnected(identityID, remoteAddr, transport string) {
}

func (s stubServices) deps() SessionDeps {
	return SessionDeps{
		Identity: &s,
		Settings: &s,
		Keys:     &s,
	}
}

func (s *stubServices) templateDeps() SessionDeps {
	return SessionDeps{
		Identity:  s,
		Settings:  s,
		Keys:      s,
		Templates: s,
	}
}

func (s *stubServices) backupDeps() SessionDeps {
	return SessionDeps{
		Identity: s,
		Backups:  s,
	}
}

func TestSessionAuthenticateSuccess(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetUnlocked()

	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:  protocol.NewSensitiveBytes("secret"),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, stubServices{
		runtime:     ir,
		unlockOK:    true,
		newIdentity: auth.NewDefaultIdentity("ipc-passphrase"),
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
	if sessionCtx.TargetIdentityID != auth.DefaultIdentityID {
		t.Fatalf("SessionContext().TargetIdentityID = %q, want %q", sessionCtx.TargetIdentityID, auth.DefaultIdentityID)
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
	if sessionCtx.AdminPrincipal.ID != auth.DefaultIdentityID {
		t.Fatalf("SessionContext().AdminPrincipal.ID = %q, want %q", sessionCtx.AdminPrincipal.ID, auth.DefaultIdentityID)
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

func TestSessionAuthenticateOutcomeHandlesLocalInitialize(t *testing.T) {
	initMsg, err := protocol.MarshalAdminMessage(protocol.InitializeStoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeInitializeStore, ID: "init-1"},
		Passphrase:  protocol.NewSensitiveBytes("new-passphrase"),
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := &stubServices{
		initializeStoreResult: InitializeStoreResult{
			Success:     true,
			MetadataDir: "/data/identities/default",
		},
	}
	conn := &queueConn{reads: [][]byte{initMsg}}
	session := NewSession(conn, SessionDeps{Identity: svc})
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

func TestSessionDispatchSettingsRequestsPreserveRequestID(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{
		Identity: svc,
		Settings: svc,
	})
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	if !session.Dispatch([]byte(`{"kind":"request","type":"get_admin_settings","id":"settings-1"}`)) {
		t.Fatal("Dispatch(get_admin_settings) = false, want true")
	}
	var adminSettings protocol.AdminSettingsMessage
	decodeOnlyMessage(t, conn, &adminSettings)
	if adminSettings.ID != "settings-1" {
		t.Fatalf("admin settings id = %q, want settings-1", adminSettings.ID)
	}
	conn.writes = nil

	if !session.Dispatch([]byte(`{"kind":"request","type":"get_policy_settings","id":"policy-1"}`)) {
		t.Fatal("Dispatch(get_policy_settings) = false, want true")
	}
	var policySettings protocol.PolicySettingsMessage
	decodeOnlyMessage(t, conn, &policySettings)
	if policySettings.ID != "policy-1" {
		t.Fatalf("policy settings id = %q, want policy-1", policySettings.ID)
	}
}

func TestSessionAuthenticateDefaultsToPreboundIdentity(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            "alice",
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetUnlocked()

	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:  protocol.NewSensitiveBytes("secret"),
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
	session.SetPreboundIdentityID("alice")

	if !session.Authenticate() {
		t.Fatal("Authenticate() = false, want true")
	}
	if len(svc.resolveIDs) != 1 || svc.resolveIDs[0] != "alice" {
		t.Fatalf("ResolveIdentity IDs = %v, want [alice]", svc.resolveIDs)
	}
	if session.TargetIdentityID() != "alice" {
		t.Fatalf("TargetIdentityID() = %q, want alice", session.TargetIdentityID())
	}
}

func TestSessionAuthenticateRejectsMismatchedPreboundIdentityBeforeUnlock(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            "bob",
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})

	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		IdentityID:  "bob",
		Passphrase:  protocol.NewSensitiveBytes("secret"),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	svc := &stubServices{
		runtime:  ir,
		unlockOK: true,
	}
	session := NewSession(conn, svc.templateDeps())
	session.SetAuthMethod("ssh-passphrase")
	session.SetPreboundIdentityID("alice")

	if session.Authenticate() {
		t.Fatal("Authenticate() = true, want false")
	}
	if len(svc.resolveIDs) != 0 {
		t.Fatalf("ResolveIdentity IDs = %v, want none", svc.resolveIDs)
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
	if result.Success || result.Code != protocol.ErrCodeAuthenticationFailed || result.Error != "authentication failed" {
		t.Fatalf("auth result = %+v, want authentication failure", result)
	}
}

func TestSessionAuthenticateRejectsUnboundNonProductIdentityBeforeResolve(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            "alice",
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})

	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		IdentityID:  "alice",
		Passphrase:  protocol.NewSensitiveBytes("secret"),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	svc := &stubServices{
		runtime:  ir,
		unlockOK: true,
	}
	session := NewSession(conn, svc.templateDeps())

	if session.Authenticate() {
		t.Fatal("Authenticate() = true, want false")
	}
	if len(svc.resolveIDs) != 0 {
		t.Fatalf("ResolveIdentity IDs = %v, want none", svc.resolveIDs)
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
	if result.Success || result.Code != protocol.ErrCodeAuthenticationFailed || result.Error != "authentication failed" {
		t.Fatalf("auth result = %+v, want authentication failure", result)
	}
}

func TestSessionAuthenticateRetriesInvalidPassphrase(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetUnlocked()

	msg1, _ := json.Marshal(protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:  protocol.NewSensitiveBytes("wrong"),
	})
	msg2, _ := json.Marshal(protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		Passphrase:  protocol.NewSensitiveBytes("right"),
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

func TestSessionAuthenticateResolveIdentityFailureIsGeneric(t *testing.T) {
	authMsg, err := json.Marshal(protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
		IdentityID:  "missing",
		Passphrase:  protocol.NewSensitiveBytes("secret"),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := &queueConn{reads: [][]byte{authMsg}}
	session := NewSession(conn, stubServices{
		resolveErr: errors.New("unsupported identity"),
	}.deps())

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

func TestSessionBindUpdatesSessionContext(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
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
	if sessionCtx.TargetIdentityID != auth.DefaultIdentityID {
		t.Fatalf("TargetIdentityID = %q, want %q", sessionCtx.TargetIdentityID, auth.DefaultIdentityID)
	}
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
	ir := identity.New(identity.Config{
		ID:            "alice",
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
