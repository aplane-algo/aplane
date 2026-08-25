// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	algocrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type SessionState int

const (
	StateConnected SessionState = iota
	StateDisplacing
	StateAuthenticated
	StateClosed
)

type AuthOutcome int

const (
	AuthOutcomeFailed AuthOutcome = iota
	AuthOutcomeAuthenticated
	AuthOutcomeBootstrapHandled
)

// Session owns one admin client protocol lifecycle.
type Session struct {
	conn               adminproto.AdminConn
	productServices    ProductServices
	settingsServices   SettingsServices
	keyServices        KeyServices
	backupServices     BackupServices
	templateServices   TemplateServices
	inspectionServices StoreInspectionServices
	authorizer         auth.Authorizer
	audit              AuthorizationAudit
	nodeFailure        func() error

	mu                  sync.Mutex
	state               SessionState
	authenticatedOnly   bool
	identity            *auth.Identity
	bound               *productruntime.Runtime
	method              string
	context             SessionContext
	ctx                 context.Context
	cancel              context.CancelFunc
	activeBackupExports map[backupExportAuditKey]struct{}
}

type backupExportAuditKey struct {
	fileName string
}

// markBackupExportChunk returns true when this successful read starts an
// unaudited archive transfer. Offset zero explicitly starts a new transfer;
// a client that starts elsewhere is still audited on its first successful
// read. EOF closes the inferred transfer so a later read is audited again.
func (s *Session) markBackupExportChunk(fileName string, offset int64, eof bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := backupExportAuditKey{fileName: fileName}
	_, active := s.activeBackupExports[key]
	started := offset == 0 || !active
	if eof {
		delete(s.activeBackupExports, key)
		return started
	}
	if s.activeBackupExports == nil {
		s.activeBackupExports = make(map[backupExportAuditKey]struct{})
	}
	s.activeBackupExports[key] = struct{}{}
	return started
}

func NewSession(conn adminproto.AdminConn, deps SessionDeps) *Session {
	method := "ipc-passphrase"
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		conn:               conn,
		productServices:    deps.Product,
		settingsServices:   deps.Settings,
		keyServices:        deps.Keys,
		backupServices:     deps.Backups,
		templateServices:   deps.Templates,
		inspectionServices: deps.Inspection,
		authorizer:         deps.Authorizer,
		audit:              deps.Audit,
		nodeFailure:        deps.NodeFailure,
		state:              StateConnected,
		method:             method,
		context:            newSessionContext(method, conn),
		ctx:                ctx,
		cancel:             cancel,
	}
}

func (s *Session) authorize(requestID string, action auth.Action, resource auth.Resource) bool {
	if s.BoundRuntime() == nil {
		_ = s.SendError(requestID, protocol.ErrCodeNoRuntimeBound, "no product runtime bound to session")
		return false
	}
	identity := s.Identity()
	if s.authorizer != nil && identity == nil {
		_ = s.SendError(requestID, protocol.ErrCodeNoRuntimeBound, "no product runtime bound to session")
		return false
	}
	if err := s.authorizeIdentity(identity, action, resource); err != nil {
		s.logAuthorizationDenied(identity, action, resource, err.Error())
		_ = s.SendError(requestID, protocol.ErrCodeAuthorizationDenied, "authorization denied")
		return false
	}
	return true
}

func (s *Session) authorizeIdentity(identity *auth.Identity, action auth.Action, resource auth.Resource) error {
	if s.authorizer == nil {
		return nil
	}
	if identity == nil {
		return auth.ErrUnauthorized
	}
	ctx := auth.ContextWithIdentity(context.Background(), identity)
	return s.authorizer.Authorize(ctx, identity, action, resource)
}

func (s *Session) logAuthorizationDenied(identity *auth.Identity, action auth.Action, resource auth.Resource, reason string) {
	if s.audit == nil {
		return
	}
	ctx := s.SessionContext()
	principal := principalFromIdentity(identity)
	if ctx.AdminPrincipal.ID == "" {
		ctx.AdminPrincipal = principal
	}
	if ctx.RequesterPrincipal.ID == "" {
		ctx.RequesterPrincipal = principal
	}
	if ctx.ApproverPrincipal.ID == "" {
		ctx.ApproverPrincipal = principal
	}
	s.audit.LogAuthorizationDenied(ctx, action, resource, reason)
}

// Authenticate performs the current admin passphrase handshake for one
// session. It preserves the existing auth_required/auth/auth_result flow.
func (s *Session) Authenticate() bool {
	return s.AuthenticateOutcome() == AuthOutcomeAuthenticated
}

// AuthenticateOutcome performs the admin handshake and returns whether the
// connection authenticated, failed, or handled a one-shot bootstrap request.
func (s *Session) AuthenticateOutcome() AuthOutcome {
	authReq := protocol.AuthRequiredMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeAuthRequired},
		ProtocolVersion: protocol.CurrentAdminProtocolVersion(),
	}
	if err := s.WriteJSON(authReq); err != nil {
		return AuthOutcomeFailed
	}

	for {
		raw, err := s.conn.ReadMessage()
		if err != nil {
			return AuthOutcomeFailed
		}

		base, err := protocol.ParseAdminBaseMessage(raw)
		if err != nil {
			s.sendAuthResult(false, protocol.ErrCodeInvalidMessageFormat, "invalid message format")
			return AuthOutcomeFailed
		}
		if base.Type == protocol.MsgTypeInitializeStore {
			return s.handlePreAuthInitialize(base.ID, raw)
		}
		if base.Type != protocol.MsgTypeAuth && base.Type != protocol.MsgTypeAuthOnly {
			s.sendAuthResult(false, protocol.ErrCodeExpectedAuthMessage, "expected auth message")
			return AuthOutcomeFailed
		}

		var versionEnvelope struct {
			ProtocolVersion *protocol.ProtocolVersion `json:"protocol_version"`
		}
		if err := json.Unmarshal(raw, &versionEnvelope); err != nil {
			s.sendAuthResult(false, protocol.ErrCodeInvalidAuthMessage, "invalid auth message format")
			return AuthOutcomeFailed
		}
		if ok, errMsg := validateAdminProtocolVersion(versionEnvelope.ProtocolVersion); !ok {
			s.sendAuthResult(false, protocol.ErrCodeInvalidAuthMessage, errMsg)
			return AuthOutcomeFailed
		}

		var authMsg protocol.AuthMessage
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&authMsg); err != nil {
			authMsg.Passphrase.Zero()
			s.sendAuthResult(false, protocol.ErrCodeInvalidAuthMessage, "invalid auth message format")
			return AuthOutcomeFailed
		}

		if s.nodeFailure != nil && s.nodeFailure() != nil {
			authMsg.Passphrase.Zero()
			s.sendAuthResult(false, protocol.ErrCodeNodeFailClosed, "signer node is fail-closed; restart required")
			return AuthOutcomeFailed
		}

		ir := s.productServices.ProductRuntime()
		if ir == nil {
			authMsg.Passphrase.Zero()
			s.sendAuthResult(false, protocol.ErrCodeAuthenticationFailed, "authentication failed")
			return AuthOutcomeFailed
		}

		passphraseBytes := authMsg.Passphrase.Clone()
		authMsg.Passphrase.Zero()
		if err := s.productServices.VerifyPassphrase(passphraseBytes); err != nil {
			zeroBytes(passphraseBytes)
			s.sendAuthResult(false, protocol.ErrCodeInvalidPassphrase, "invalid passphrase")
			continue
		}

		sessionIdentity := s.productServices.NewSessionIdentity(s.method)
		principal := principalFromIdentity(sessionIdentity)
		authenticateOnly := base.Type == protocol.MsgTypeAuthOnly
		if !authenticateOnly {
			unlockResource := auth.Resource{Type: "identity"}
			if err := s.authorizeIdentity(sessionIdentity, auth.ActionIdentityUnlock, unlockResource); err != nil {
				zeroBytes(passphraseBytes)
				s.logAuthorizationDenied(sessionIdentity, auth.ActionIdentityUnlock, unlockResource, err.Error())
				s.sendAuthResult(false, protocol.ErrCodeAuthorizationDenied, "authorization denied")
				return AuthOutcomeFailed
			}
		}

		if !authenticateOnly && !ir.IsUnlocked() {
			success, _, errMsg, code := s.productServices.UnlockIdentity(passphraseBytes)
			zeroBytes(passphraseBytes)
			if !success {
				if code == "" {
					code = protocol.ErrCodeUnlockFailed
				}
				s.sendAuthResult(false, code, "auth ok but unlock failed: "+errMsg)
				return AuthOutcomeFailed
			}
		} else {
			zeroBytes(passphraseBytes)
		}

		s.mu.Lock()
		s.authenticatedOnly = authenticateOnly
		s.identity = sessionIdentity
		s.bound = ir
		s.state = StateAuthenticated
		s.context.AdminPrincipal = principal
		s.context.RequesterPrincipal = principal
		s.context.ApproverPrincipal = principal
		s.context.AuthMethod = s.method
		s.mu.Unlock()
		s.sendAuthResult(true, "", "")
		return AuthOutcomeAuthenticated
	}
}

func (s *Session) handlePreAuthInitialize(requestID string, raw []byte) AuthOutcome {
	if s.nodeFailure != nil && s.nodeFailure() != nil {
		_ = s.WriteJSON(ProtocolInitializeStoreResultMessage(requestID, adminproto.InitializeStoreResult{
			Code:  protocol.ErrCodeNodeFailClosed,
			Error: "signer node is fail-closed; restart required",
		}))
		return AuthOutcomeBootstrapHandled
	}
	if s.Transport() != "ipc" {
		_ = s.WriteJSON(ProtocolInitializeStoreResultMessage(requestID, adminproto.InitializeStoreResult{
			Code:  protocol.ErrCodeAuthorizationDenied,
			Error: "initialize_store is only available over local IPC",
		}))
		return AuthOutcomeBootstrapHandled
	}
	if s.productServices == nil {
		_ = s.WriteJSON(ProtocolInitializeStoreResultMessage(requestID, adminproto.InitializeStoreResult{
			Code:  protocol.ErrCodeInternal,
			Error: "identity service unavailable",
		}))
		return AuthOutcomeBootstrapHandled
	}
	var msg protocol.InitializeStoreMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		_ = s.WriteJSON(ProtocolInitializeStoreResultMessage(requestID, adminproto.InitializeStoreResult{
			Code:  protocol.ErrCodeInvalidRequest,
			Error: "invalid initialize store message",
		}))
		return AuthOutcomeBootstrapHandled
	}
	defer msg.Passphrase.Zero()
	passphrase := msg.Passphrase.Clone()
	defer zeroBytes(passphrase)
	result := s.productServices.InitializeStore(adminproto.InitializeStoreRequest{Passphrase: passphrase})
	_ = s.WriteJSON(ProtocolInitializeStoreResultMessage(msg.ID, result))
	return AuthOutcomeBootstrapHandled
}

func (s *Session) WriteJSON(v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	return s.conn.WriteMessage(data)
}

func (s *Session) Close() error {
	s.mu.Lock()
	s.state = StateClosed
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// Context is canceled when the admin session is closed.
func (s *Session) Context() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func (s *Session) BoundRuntime() *productruntime.Runtime {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bound
}

// AuthenticatedOnly reports whether the session authenticated without unlock
// authority. Such sessions are non-owning observers and may dispatch only the
// explicit public-read request allowlist.
func (s *Session) AuthenticatedOnly() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authenticatedOnly
}

func (s *Session) Identity() *auth.Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identity
}

func (s *Session) SessionContext() SessionContext {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSessionContext(s.context)
}

func (s *Session) SessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.context.SessionID
}

func (s *Session) Transport() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.context.Transport
}

func (s *Session) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Session) Bind(identity *auth.Identity, bound *productruntime.Runtime) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity = identity
	s.bound = bound
	principal := principalFromIdentity(identity)
	s.context.AdminPrincipal = principal
	s.context.RequesterPrincipal = principal
	s.context.ApproverPrincipal = principal
	if bound != nil {
		s.state = StateAuthenticated
	}
}

func (s *Session) SetAuthMethod(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if method != "" {
		s.method = method
		s.context.AuthMethod = method
	}
}

func (s *Session) SetTransportInfo(transport, remoteAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if transport != "" {
		s.context.Transport = transport
	}
	if remoteAddr != "" {
		s.context.RemoteAddr = remoteAddr
	}
}

func validateAdminProtocolVersion(clientVersion *protocol.ProtocolVersion) (bool, string) {
	if clientVersion == nil {
		return false, "admin protocol version is required"
	}
	if clientVersion.Major != protocol.AdminProtocolVersionMajor {
		return false, fmt.Sprintf("admin protocol major version mismatch: client=%d server=%d",
			clientVersion.Major, protocol.AdminProtocolVersionMajor)
	}
	if clientVersion.Minor != protocol.AdminProtocolVersionMinor {
		slog.Warn("admin protocol minor version mismatch",
			"client_minor", clientVersion.Minor,
			"server_minor", protocol.AdminProtocolVersionMinor)
	}
	return true, ""
}

func (s *Session) Conn() adminproto.AdminConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *Session) productOrBoundRuntime() *productruntime.Runtime {
	ir := s.BoundRuntime()
	if ir == nil && s.productServices != nil {
		ir = s.productServices.ProductRuntime()
	}
	return ir
}

func (s *Session) requireBoundRuntime(requestID string) *productruntime.Runtime {
	ir := s.BoundRuntime()
	if ir != nil {
		return ir
	}
	_ = s.SendError(requestID, protocol.ErrCodeNoRuntimeBound, "no product runtime bound to session")
	return nil
}

func (s *Session) requireUnlockedRuntime(requestID string) *productruntime.Runtime {
	ir := s.requireBoundRuntime(requestID)
	if ir == nil {
		return nil
	}
	if ir.IsUnlocked() {
		return ir
	}
	_ = s.SendError(requestID, protocol.ErrCodeSignerLocked, "Signer is locked")
	return nil
}

func (s *Session) requireRecoveryAdminRuntime(requestID string) *productruntime.Runtime {
	ir := s.requireBoundRuntime(requestID)
	if ir == nil {
		return nil
	}
	if ir.IsUnlocked() || ir.IsRecovery() {
		return ir
	}
	_ = s.SendError(requestID, protocol.ErrCodeSignerLocked, "Signer is locked")
	return nil
}

func (s *Session) sendAuthResult(success bool, code, errMsg string) {
	_ = s.WriteJSON(ProtocolAuthResultMessage(success, code, errMsg))
}

func zeroBytes(data []byte) {
	algocrypto.ZeroBytes(data)
}
