// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
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
	manager  *adminproto.SessionManager

	writeMu sync.Mutex
}

// NewIPCServer creates a new IPC server.
func NewIPCServer(path string, signer *Signer) *IPCServer {
	return &IPCServer{
		path:    path,
		signer:  signer,
		manager: adminproto.NewSessionManager(),
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
		go s.acceptAdminSession(adminproto.NewUnixAdminConn(conn, nil, &s.writeMu), "ipc", "ipc-passphrase", "")
	}
}

// displacementTimeout is the maximum time to wait for a displacement confirmation.
const displacementTimeout = 30 * time.Second

// offerDisplacement sends a client_exists message to the new connection and waits
// for a displace_confirm response. If confirmed, it displaces the old client.
// Returns the bufio.Reader (to avoid data loss from buffering) and true on success.
// This legacy IPC helper is product-mode scoped; identity-aware paths should
// call offerDisplacementSession with an explicit identity.
func (s *IPCServer) offerDisplacement(newConn net.Conn) bool {
	identityID := auth.CurrentProductIdentityID()
	return s.offerDisplacementSession(identityID, s.activeIdentitySession(identityID), adminproto.NewUnixAdminConn(newConn, nil, &s.writeMu))
}

func (s *IPCServer) offerDisplacementSession(identityID string, active *adminproto.Session, newConn adminproto.AdminConn) bool {
	confirmed, displaced := adminproto.OfferDisplacement(identityID, s.sessionManager(), active, newConn, displacementTimeout)
	if displaced {
		logWarnf("existing apadmin client displaced by new connection")
	}
	return confirmed
}

// handleClient handles a single IPC client connection.
func (s *IPCServer) handleClient(conn net.Conn) {
	s.acceptAdminSession(adminproto.NewUnixAdminConn(conn, nil, &s.writeMu), "ipc", "ipc-passphrase", "")
}

func (s *IPCServer) acceptAdminSession(adminConn adminproto.AdminConn, transport, authMethod, preboundIdentityID string) {
	session := adminproto.NewSession(adminConn, s.signer.adminSessionDeps())
	session.SetAuthMethod(authMethod)
	session.SetTransportInfo(transport, adminConn.RemoteAddr())
	session.SetPreboundIdentityID(preboundIdentityID)

	pendingIdentityID := preboundIdentityID
	var active *adminproto.Session
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
		if !s.offerDisplacementSession(pendingIdentityID, active, adminConn) {
			s.clearPendingSession(preboundIdentityID, session)
			_ = session.Close()
			return
		}
	}
	s.handleRegisteredClient(session, transport, preboundIdentityID)
}

func (s *IPCServer) handleRegisteredClient(session *adminproto.Session, transport, preboundIdentityID string) {
	// Track whether we successfully authenticated (for cleanup logic)
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

		// Only do disconnect cleanup if we were the active authenticated client.
		// Displaced clients should not fail pending requests or lock the signer,
		// because the new client is taking over.
		if authenticated && wasActiveClient {
			// Route disconnect cleanup through the bound identity
			if boundIR != nil {
				if s.signer != nil {
					s.signer.adminServices().LogSessionDisconnectedContext(session.SessionContext())
				}
				boundIR.FailAllPendingApprovals("apadmin disconnected")

				// Lock behavior is driven by the live identity runtime config,
				// which should already reflect any stored overrides.
				if boundIR.Config().LockOnDisconnect() {
					boundIR.Lock()
					logWarnf("apadmin client disconnected - signer locked")
				} else {
					timeout := boundIR.Config().SessionTimeout()
					if timeout > 0 {
						logWarnf("apadmin disconnected - signer remains unlocked until timeout: %s", timeout)
					} else {
						logWarnf("apadmin disconnected - signer remains unlocked with no timeout")
					}
				}
			}
		}
	}()

	// Authenticate the client before allowing normal operations. A fresh store
	// can also handle one local initialize request before passphrase auth exists.
	switch session.AuthenticateOutcome() {
	case adminproto.AuthOutcomeAuthenticated:
	case adminproto.AuthOutcomeBootstrapHandled:
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
	if active != nil && active != session {
		if !s.offerDisplacementSession(identityID, active, adminConn) {
			s.sessionManager().ClearPending(identityID, session)
			return
		}
	}
	s.sessionManager().PromoteToActive(identityID, session)
	authenticated = true

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
	return active.WriteJSON(adminproto.ProtocolSignRequestMessage(*req)) == nil
}

// SendSignRequestCanceled tells the IPC client that a previously delivered
// signing request is no longer actionable.
func (s *IPCServer) SendSignRequestCanceled(identityID string, msg *signerapproval.SignRequestCanceled) bool {
	active := s.activeIdentitySession(identityID)
	if active == nil || msg == nil {
		return false
	}
	return active.WriteJSON(adminproto.ProtocolSignRequestCanceledMessage(*msg)) == nil
}

// SendTokenProvisioningRequest sends a token provisioning request to the IPC client.
func (s *IPCServer) SendTokenProvisioningRequest(identityID string, req *signerapproval.TokenProvisioningRequest) bool {
	active := s.activeIdentitySession(identityID)
	if active == nil {
		return false
	}
	return active.WriteJSON(adminproto.ProtocolTokenProvisioningRequestMessage(*req)) == nil
}

// NotifyLocked sends a signer_locked notification to the connected IPC client.
// This allows apadmin to transition to the unlock screen when the signer auto-locks.
func (s *IPCServer) NotifyLocked(identityID string, notification adminproto.SignerLockedNotification) {
	msg := adminproto.ProtocolSignerLockedMessage(notification)
	active := s.activeIdentitySession(identityID)
	if active == nil {
		return
	}
	_ = active.WriteJSON(msg) // Best-effort notification
}

// NotifyKeysChanged sends a keys_changed notification to the connected IPC client.
// This allows apadmin to refresh its key list when keys are added/removed.
func (s *IPCServer) NotifyKeysChanged(identityID string, notification adminproto.KeysChangedNotification) {
	msg := adminproto.ProtocolKeysChangedMessage(notification)
	active := s.activeIdentitySession(identityID)
	if active == nil {
		return
	}
	_ = active.WriteJSON(msg) // Best-effort notification
}

func (s *IPCServer) sessionManager() *adminproto.SessionManager {
	if s.manager == nil {
		s.manager = adminproto.NewSessionManager()
	}
	return s.manager
}

// activeSession is a product-mode compatibility helper for legacy tests and
// local IPC call sites that have not selected an identity explicitly.
func (s *IPCServer) activeSession() *adminproto.Session {
	return s.activeIdentitySession(auth.CurrentProductIdentityID())
}

func (s *IPCServer) activeIdentitySession(identityID string) *adminproto.Session {
	return s.sessionManager().ActiveSession(identityID)
}

func (s *IPCServer) clearPendingSession(identityID string, session *adminproto.Session) {
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
