// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"net"
	"os"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/ipcbind"
)

// IPCServer handles Unix socket connections for local IPC.
type IPCServer struct {
	listener net.Listener
	signer   *Signer
	path     string
	manager  *adminserver.SessionManager
}

// NewIPCServer creates a new IPC server.
func NewIPCServer(path string, signer *Signer) *IPCServer {
	return &IPCServer{
		path:    path,
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
}

// Start begins listening on the Unix socket.
func (s *IPCServer) Start() error {
	if err := ipcbind.ValidateBindPath(s.path); err != nil {
		return err
	}

	// Remove existing socket file if present
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	listener, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("failed to listen on IPC socket: %w", err)
	}

	// Set socket permissions (owner + group can access, for apadmin users in the service group)
	if err := os.Chmod(s.path, 0660); err != nil {
		_ = listener.Close() // Best-effort cleanup
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.listener = listener
	go s.acceptLoop()
	return nil
}

// Stop closes the IPC server.
func (s *IPCServer) Stop() {
	if s.listener != nil {
		_ = s.listener.Close() // Best-effort cleanup
	}
	if active := s.activeSession(); active != nil {
		_ = active.Close()
	}
	// Clean up socket file
	_ = os.Remove(s.path) // Best-effort cleanup
}

// acceptLoop accepts incoming IPC connections.
func (s *IPCServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Listener closed
			return
		}

		logInfof("apadmin client connected via IPC")
		go s.acceptAdminSession(adminproto.NewUnixAdminConn(conn, nil), "ipc", "ipc-passphrase", "")
	}
}

// displacementTimeout is the maximum time to wait for a displacement confirmation.
const displacementTimeout = 30 * time.Second

func (s *IPCServer) offerDisplacementSession(active *adminserver.Session, newConn adminproto.AdminConn) bool {
	confirmed, displaced := adminserver.OfferDisplacement(active, newConn, displacementTimeout)
	if displaced {
		logWarnf("existing apadmin client accepted displacement by new connection")
	}
	return confirmed
}

func (s *IPCServer) acceptAdminSession(adminConn adminproto.AdminConn, transport, authMethod, preboundIdentityID string) {
	session := adminserver.NewSession(adminConn, s.signer.adminSessionDeps())
	session.SetAuthMethod(authMethod)
	session.SetTransportInfo(transport, adminConn.RemoteAddr())
	session.SetPreboundIdentityID(preboundIdentityID)

	pendingIdentityID := preboundIdentityID
	var active *adminserver.Session
	var displacementConfirmedFor *adminserver.Session
	var ok bool
	if pendingIdentityID != "" {
		ok = s.sessionManager().RegisterPending(pendingIdentityID, session)
		active = s.activeIdentitySession(pendingIdentityID)
	} else {
		ok = s.sessionManager().RegisterPreAuthPending(session)
		pendingIdentityID = auth.CurrentProductIdentityID()
		active = s.activeIdentitySession(pendingIdentityID)
	}
	if !ok {
		errMsg := protocol.ErrorMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError},
			Error:       "another apadmin client is currently authenticating",
		}
		_ = writeJSONMessage(adminConn, errMsg)
		_ = session.Close()
		return
	}
	if active != nil {
		if !s.offerDisplacementSession(active, adminConn) {
			s.clearPendingSession(preboundIdentityID, session)
			_ = session.Close()
			return
		}
		displacementConfirmedFor = active
	}
	s.handleRegisteredClient(session, transport, preboundIdentityID, displacementConfirmedFor)
}

func (s *IPCServer) handleRegisteredClient(session *adminserver.Session, transport, preboundIdentityID string, displacementConfirmedFor *adminserver.Session) {
	// If auth unlocks an identity for this session, either the session becomes
	// the active owner or cleanup must leave the identity locked (when
	// lock_on_disconnect is set) with no pending approvals stranded.
	authenticated := false
	adminConn := session.Conn()

	defer func() {
		s.clearPendingSession(preboundIdentityID, session)
		boundIR := session.BoundRuntime()
		boundIdentityID := ""
		if boundIR != nil {
			boundIdentityID = boundIR.ID()
			s.sessionManager().ClearPending(boundIdentityID, session)
		}
		wasActiveClient := s.sessionManager().ClearActive(boundIdentityID, session)
		_ = session.Close() // Best-effort cleanup

		// Run owner cleanup whenever this authenticated session exits and no
		// active owner remains. Displaced clients skip cleanup because the
		// replacement is already active before they are notified and closed.
		if authenticated && boundIR != nil && (wasActiveClient || !s.sessionManager().HasClient(boundIdentityID)) {
			// Route disconnect cleanup through the bound identity
			if wasActiveClient && s.signer != nil {
				s.signer.adminServices().LogSessionDisconnectedContext(session.SessionContext())
			}
			boundIR.FailAllPendingApprovals("apadmin disconnected")

			// Lock behavior is driven by the live identity runtime config,
			// which should already reflect any stored overrides.
			if boundIR.Config().LockOnDisconnect() {
				boundIR.Lock()
				logWarnf("apadmin client disconnected - signer locked")
			} else {
				logWarnf("apadmin disconnected - signer remains unlocked")
			}
		}
	}()

	// Authenticate the client before allowing normal operations. A fresh store
	// can also handle one local initialize request before passphrase auth exists.
	switch session.AuthenticateOutcome() {
	case adminserver.AuthOutcomeAuthenticated:
		authenticated = true
	case adminserver.AuthOutcomeBootstrapHandled:
		return
	default:
		logWarnf("%s client authentication failed", strings.ToUpper(transport))
		return
	}
	logInfof("%s client authenticated", strings.ToUpper(transport))

	// Now register as the active client (after auth succeeds)
	// This ensures NotifyKeysChanged won't send messages during auth
	boundIR := session.BoundRuntime()
	if boundIR == nil {
		return
	}
	identityID := boundIR.ID()
	active, ok := s.sessionManager().MovePendingToIdentity(identityID, session)
	if !ok {
		logWarnf("%s client could not bind pending session to identity %q", strings.ToUpper(transport), identityID)
		return
	}
	if active != nil && active != session && active != displacementConfirmedFor {
		if !s.offerDisplacementSession(active, adminConn) {
			s.sessionManager().ClearPending(identityID, session)
			return
		}
	}
	replaced, ok := s.sessionManager().PromoteToActive(identityID, session)
	if !ok {
		logWarnf("%s client could not promote session for identity %q", strings.ToUpper(transport), identityID)
		return
	}
	if replaced != nil && replaced != session {
		if replacedIR := replaced.BoundRuntime(); replacedIR != nil {
			replacedIR.FailAllPendingApprovals("apadmin displaced")
		}
		adminserver.DisplaceSession(replaced)
	}

	if s.signer != nil {
		s.signer.adminServices().LogSessionConnectedContext(session.SessionContext())
	}

	// Send initial status after successful authentication
	_ = session.SendStatus()

	// Message loop
	for {
		line, err := adminConn.ReadMessage()
		if err != nil {
			return
		}

		// Parse base message
		base, err := protocol.ParseAdminBaseMessage(line)
		if err != nil {
			_ = session.SendError("", protocol.ErrCodeInvalidMessageFormat, "invalid message format")
			continue
		}

		// Handle message based on type
		if session.Dispatch(line) {
			continue
		}
		_ = session.SendError(base.ID, protocol.ErrCodeUnknownMessageType, "unknown message type: "+base.Type)
	}
}

// HasClient returns true if an IPC client is connected for the identity.
func (s *IPCServer) HasClient(identityID string) bool {
	return s.sessionManager().HasClient(identityID)
}

// SendSignRequest sends a signing request to the IPC client.
func (s *IPCServer) SendSignRequest(identityID string, req *signerapproval.SignRequest) bool {
	active := s.activeIdentitySession(identityID)
	if active == nil {
		return false
	}
	return active.WriteJSON(adminserver.ProtocolSignRequestMessage(*req)) == nil
}

// SendSignRequestCanceled tells the IPC client that a previously delivered
// signing request is no longer actionable.
func (s *IPCServer) SendSignRequestCanceled(identityID string, msg *signerapproval.SignRequestCanceled) bool {
	active := s.activeIdentitySession(identityID)
	if active == nil || msg == nil {
		return false
	}
	return active.WriteJSON(adminserver.ProtocolSignRequestCanceledMessage(*msg)) == nil
}

// SendTokenProvisioningRequest sends a token provisioning request to the IPC client.
func (s *IPCServer) SendTokenProvisioningRequest(identityID string, req *signerapproval.TokenProvisioningRequest) bool {
	active := s.activeIdentitySession(identityID)
	if active == nil {
		return false
	}
	return active.WriteJSON(adminserver.ProtocolTokenProvisioningRequestMessage(*req)) == nil
}

// NotifyLocked sends a signer_locked notification to the connected IPC client.
// This allows apadmin to transition to the unlock screen when the signer locks.
func (s *IPCServer) NotifyLocked(identityID string, notification adminproto.SignerLockedNotification) {
	msg := adminserver.ProtocolSignerLockedMessage(notification)
	active := s.activeIdentitySession(identityID)
	if active == nil {
		return
	}
	_ = active.WriteJSON(msg) // Best-effort notification
}

// NotifyKeysChanged sends a keys_changed notification to the connected IPC client.
// This allows apadmin to refresh its key list when keys are added/removed.
func (s *IPCServer) NotifyKeysChanged(identityID string, notification adminproto.KeysChangedNotification) {
	msg := adminserver.ProtocolKeysChangedMessage(notification)
	active := s.activeIdentitySession(identityID)
	if active == nil {
		return
	}
	_ = active.WriteJSON(msg) // Best-effort notification
}

func (s *IPCServer) sessionManager() *adminserver.SessionManager {
	if s.manager == nil {
		s.manager = adminserver.NewSessionManager()
	}
	return s.manager
}

// activeSession is a product-mode compatibility helper for legacy tests and
// local IPC call sites that have not selected an identity explicitly.
func (s *IPCServer) activeSession() *adminserver.Session {
	return s.activeIdentitySession(auth.CurrentProductIdentityID())
}

func (s *IPCServer) activeIdentitySession(identityID string) *adminserver.Session {
	return s.sessionManager().ActiveSession(identityID)
}

func (s *IPCServer) clearPendingSession(identityID string, session *adminserver.Session) {
	s.sessionManager().ClearPreAuthPending(session)
	if identityID != "" {
		s.sessionManager().ClearPending(identityID, session)
	}
}

func writeJSONMessage(conn adminproto.AdminConn, v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	return conn.WriteMessage(data)
}
